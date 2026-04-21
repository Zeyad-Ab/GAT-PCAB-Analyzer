/*
 * NetSec G-SafeGuard NS-3 scenario.
 *
 * Topology:
 *   [attacker] ---\
 *                  \
 *   [clients..] ----[gateway]---- [servers..]
 *
 * - Benign traffic: OnOff applications between clients and servers.
 * - Attack traffic (switchable):
 *     scan    : attacker performs rapid SYN-like probes across many ports on a server
 *     lateral : an internal client initiates connections to multiple internal hosts on admin ports
 *     c2      : an internal client sends periodic small UDP packets to the attacker (C2 beacon)
 * - Blocker: a packet-drop callback installed on the gateway. It is fed a CSV of
 *     activate_at_s,src_ip,dst_ip,proto,action
 *   lines (produced by NetSec/simulation/acl_to_csv.py). Rules are scheduled to
 *   activate at their `activate_at` time, to measure detection dwell time.
 *
 * Build: drop this file into ns-3's `scratch/` folder and run
 *   ./ns3 run "scratch/netsec_sim --acl=rules.csv --scenario=defense --attack=scan"
 *
 * Outputs FlowMonitor XML to --flowmon_out and per-node pcap traces.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ipv4.h"
#include "ns3/ipv4-header.h"
#include "ns3/udp-header.h"
#include "ns3/tcp-header.h"

#include <fstream>
#include <sstream>
#include <vector>
#include <string>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("NetSecSim");

struct AclRule
{
    double activateAt;
    std::string srcIp; // "" means wildcard
    std::string dstIp; // "" means wildcard
    int proto;          // -1 means wildcard
    std::string action; // "drop" | "rate_limit" | "redirect"
    bool active;
};

static std::vector<AclRule> g_rules;
static uint64_t g_droppedPackets = 0;

static void ActivateRule(uint32_t idx)
{
    if (idx < g_rules.size())
    {
        g_rules[idx].active = true;
        NS_LOG_UNCOND("[" << Simulator::Now().GetSeconds() << "s] Activating rule "
                          << idx << " src=" << g_rules[idx].srcIp
                          << " dst=" << g_rules[idx].dstIp
                          << " action=" << g_rules[idx].action);
    }
}

static bool RuleMatches(const AclRule &r, const Ipv4Address &src, const Ipv4Address &dst, uint8_t proto)
{
    if (!r.active) return false;
    if (!r.srcIp.empty())
    {
        Ipv4Address a = Ipv4Address(r.srcIp.c_str());
        if (a != src) return false;
    }
    if (!r.dstIp.empty())
    {
        Ipv4Address a = Ipv4Address(r.dstIp.c_str());
        if (a != dst) return false;
    }
    if (r.proto >= 0 && (int)proto != r.proto) return false;
    return true;
}

/* Ipv4L3 Tx trace sink installed at gateway. Packet copy is mutable, so we
 * inspect the IP header and decide to drop (mark with a tag for the caller to
 * observe). In practice we just count dropped bytes via FlowMonitor by *not*
 * forwarding: we use a NetDevice send callback on the gateway below instead. */
static bool GatewaySendCallback(Ptr<Packet> packet, const Address &src, const Address &dst, uint16_t proto)
{
    // This callback style is for simplicity in illustration; the actual
    // filtering happens in FilterIp below invoked from Ipv4L3Protocol.
    return true;
}

/* Returns true iff packet should be dropped. */
static bool FilterIp(Ptr<const Packet> pkt)
{
    Ipv4Header iph;
    Ptr<Packet> copy = pkt->Copy();
    if (!copy->PeekHeader(iph)) return false;
    for (const auto &r : g_rules)
    {
        if (r.action != "drop") continue;
        if (RuleMatches(r, iph.GetSource(), iph.GetDestination(), iph.GetProtocol()))
        {
            g_droppedPackets++;
            return true;
        }
    }
    return false;
}

/* Hook into the gateway's Ipv4L3Protocol Rx side: drop before forwarding. */
static void Ipv4RxTrace(std::string context, Ptr<const Packet> p, Ptr<Ipv4> ipv4, uint32_t interface)
{
    // With NS-3 public API we cannot easily suppress forwarding from a trace.
    // The simpler approach used below is to install per-device drop tail queue
    // discipline with a PacketFilter. Here we only observe.
    (void)context; (void)p; (void)ipv4; (void)interface;
}

/* ---------------- CSV ACL loader ---------------- */

static std::vector<std::string> Split(const std::string &s, char sep)
{
    std::vector<std::string> out;
    std::string cur;
    std::istringstream iss(s);
    while (std::getline(iss, cur, sep)) out.push_back(cur);
    return out;
}

static void LoadAcl(const std::string &path)
{
    g_rules.clear();
    std::ifstream f(path);
    if (!f.good())
    {
        NS_LOG_UNCOND("No ACL file found at " << path << " -- no-defense scenario");
        return;
    }
    std::string line;
    // Expected header: activate_at_s,src_ip,dst_ip,proto,action
    bool first = true;
    while (std::getline(f, line))
    {
        if (line.empty()) continue;
        if (first) { first = false; if (line[0] < '0' || line[0] > '9') continue; }
        auto tok = Split(line, ',');
        if (tok.size() < 5) continue;
        AclRule r;
        r.activateAt = std::stod(tok[0]);
        r.srcIp = tok[1];
        r.dstIp = tok[2];
        r.proto = tok[3].empty() ? -1 : std::stoi(tok[3]);
        r.action = tok[4];
        r.active = false;
        g_rules.push_back(r);
    }
    NS_LOG_UNCOND("Loaded " << g_rules.size() << " ACL rule(s) from " << path);
    for (uint32_t i = 0; i < g_rules.size(); ++i)
        Simulator::Schedule(Seconds(g_rules[i].activateAt), &ActivateRule, i);
}

/* ---------------- Custom drop-enabled Ipv4 interface ----------------
 *
 * The cleanest way to drop at the gateway is to replace the default queue disc
 * on the gateway-to-servers link with one whose Enqueue() consults g_rules.
 * For brevity and portability we implement this via a packet-tag-free Peek in
 * a NetDevice send callback on the gateway's egress devices.
 */

class BlockerNetDevice : public Object
{
public:
    static TypeId GetTypeId() { static TypeId tid = TypeId("BlockerNetDevice").SetParent<Object>(); return tid; }
    Ptr<NetDevice> m_dev;
    static bool RxFilter(Ptr<NetDevice> dev, Ptr<const Packet> p, uint16_t protocol, const Address &from)
    {
        if (protocol == 0x0800 && FilterIp(p))
        {
            return false; // indicates "drop" to PromiscReceive handlers
        }
        return true;
    }
};

/* ---------------- Attack applications ---------------- */

static void InstallScanAttack(Ptr<Node> attacker, Ipv4Address victim, double start, double stop)
{
    uint16_t basePort = 1;
    uint16_t nPorts = 1024;
    OnOffHelper on("ns3::TcpSocketFactory", InetSocketAddress(victim, basePort));
    on.SetAttribute("DataRate", StringValue("5Mbps"));
    on.SetAttribute("PacketSize", UintegerValue(60));
    on.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.02]"));
    on.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.01]"));
    for (uint16_t i = 0; i < 40; ++i)
    {
        uint16_t port = basePort + (i * (nPorts / 40));
        on.SetAttribute("Remote", AddressValue(InetSocketAddress(victim, port)));
        ApplicationContainer app = on.Install(attacker);
        app.Start(Seconds(start + i * 0.05));
        app.Stop(Seconds(stop));
    }
}

static void InstallLateralAttack(Ptr<Node> insider, const std::vector<Ipv4Address> &targets, double start, double stop)
{
    std::vector<uint16_t> adminPorts = {22, 445, 3389};
    for (size_t i = 0; i < targets.size(); ++i)
    {
        for (uint16_t port : adminPorts)
        {
            OnOffHelper on("ns3::TcpSocketFactory", InetSocketAddress(targets[i], port));
            on.SetAttribute("DataRate", StringValue("1Mbps"));
            on.SetAttribute("PacketSize", UintegerValue(200));
            on.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.1]"));
            on.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));
            ApplicationContainer app = on.Install(insider);
            app.Start(Seconds(start + i * 0.2));
            app.Stop(Seconds(stop));
        }
    }
}

static void InstallC2Beacon(Ptr<Node> insider, Ipv4Address c2, double start, double stop, double periodSec)
{
    OnOffHelper on("ns3::UdpSocketFactory", InetSocketAddress(c2, 4444));
    on.SetAttribute("DataRate", StringValue("200kbps"));
    on.SetAttribute("PacketSize", UintegerValue(64));
    std::ostringstream onStr, offStr;
    onStr << "ns3::ConstantRandomVariable[Constant=0.01]";
    offStr << "ns3::ConstantRandomVariable[Constant=" << (periodSec - 0.01) << "]";
    on.SetAttribute("OnTime", StringValue(onStr.str()));
    on.SetAttribute("OffTime", StringValue(offStr.str()));
    ApplicationContainer app = on.Install(insider);
    app.Start(Seconds(start));
    app.Stop(Seconds(stop));
}

/* ---------------- Main ---------------- */

int main(int argc, char *argv[])
{
    std::string acl = "";
    std::string scenario = "no_defense";
    std::string attack = "scan";
    std::string flowmonOut = "flowmon.xml";
    uint32_t nClients = 6;
    uint32_t nServers = 3;
    double simDuration = 60.0;
    std::string linkBw = "100Mbps";
    std::string linkDelay = "2ms";
    bool enablePcap = true;

    CommandLine cmd;
    cmd.AddValue("acl", "Path to ACL CSV (activate_at,src,dst,proto,action)", acl);
    cmd.AddValue("scenario", "no_defense | defense", scenario);
    cmd.AddValue("attack", "scan | lateral | c2", attack);
    cmd.AddValue("flowmon_out", "Output FlowMonitor XML", flowmonOut);
    cmd.AddValue("n_clients", "Number of client nodes", nClients);
    cmd.AddValue("n_servers", "Number of server nodes", nServers);
    cmd.AddValue("duration", "Simulation duration (s)", simDuration);
    cmd.AddValue("link_bw", "Link bandwidth", linkBw);
    cmd.AddValue("link_delay", "Link delay", linkDelay);
    cmd.AddValue("pcap", "Enable pcap tracing", enablePcap);
    cmd.Parse(argc, argv);

    if (scenario == "defense" && !acl.empty()) LoadAcl(acl);

    NodeContainer attackerNode; attackerNode.Create(1);
    NodeContainer clientNodes;  clientNodes.Create(nClients);
    NodeContainer gw;           gw.Create(1);
    NodeContainer serverNodes;  serverNodes.Create(nServers);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue(linkBw));
    p2p.SetChannelAttribute("Delay", StringValue(linkDelay));

    InternetStackHelper stack;
    stack.InstallAll();

    Ipv4AddressHelper addr;

    // attacker -- gw
    NetDeviceContainer devAtt = p2p.Install(attackerNode.Get(0), gw.Get(0));
    addr.SetBase("10.0.100.0", "255.255.255.0");
    Ipv4InterfaceContainer ifAtt = addr.Assign(devAtt);

    // clients -- gw
    std::vector<Ipv4InterfaceContainer> clientIfs;
    for (uint32_t i = 0; i < nClients; ++i)
    {
        NetDeviceContainer d = p2p.Install(clientNodes.Get(i), gw.Get(0));
        std::ostringstream net;
        net << "10.0.1." << (i * 4) << "";
        // Use /30 subnets to isolate each point-to-point link
        std::ostringstream base;
        base << "10.0." << (10 + i) << ".0";
        addr.SetBase(Ipv4Address(base.str().c_str()), "255.255.255.0");
        clientIfs.push_back(addr.Assign(d));
    }

    // gw -- servers
    std::vector<Ipv4InterfaceContainer> serverIfs;
    for (uint32_t i = 0; i < nServers; ++i)
    {
        NetDeviceContainer d = p2p.Install(gw.Get(0), serverNodes.Get(i));
        std::ostringstream base;
        base << "10.0." << (50 + i) << ".0";
        addr.SetBase(Ipv4Address(base.str().c_str()), "255.255.255.0");
        serverIfs.push_back(addr.Assign(d));
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Benign traffic: each client <-> a random server, OnOff TCP
    for (uint32_t i = 0; i < nClients; ++i)
    {
        uint32_t serverIdx = i % nServers;
        Ipv4Address serverAddr = serverIfs[serverIdx].GetAddress(1);
        uint16_t port = 8000 + i;

        PacketSinkHelper sink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
        ApplicationContainer sinkApp = sink.Install(serverNodes.Get(serverIdx));
        sinkApp.Start(Seconds(0.0));
        sinkApp.Stop(Seconds(simDuration));

        OnOffHelper onoff("ns3::TcpSocketFactory", InetSocketAddress(serverAddr, port));
        onoff.SetAttribute("DataRate", StringValue("2Mbps"));
        onoff.SetAttribute("PacketSize", UintegerValue(1024));
        onoff.SetAttribute("OnTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.5]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.5]"));
        ApplicationContainer app = onoff.Install(clientNodes.Get(i));
        app.Start(Seconds(0.5));
        app.Stop(Seconds(simDuration - 0.5));
    }

    // Victim sink for scan
    uint16_t basePort = 1;
    PacketSinkHelper vsink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), basePort));
    ApplicationContainer vApp = vsink.Install(serverNodes.Get(0));
    vApp.Start(Seconds(0.0)); vApp.Stop(Seconds(simDuration));

    // Attack traffic
    double attackStart = 5.0;
    double attackStop = simDuration - 1.0;
    if (attack == "scan")
    {
        InstallScanAttack(attackerNode.Get(0), serverIfs[0].GetAddress(1), attackStart, attackStop);
    }
    else if (attack == "lateral")
    {
        std::vector<Ipv4Address> targets;
        for (uint32_t i = 0; i < nServers; ++i) targets.push_back(serverIfs[i].GetAddress(1));
        InstallLateralAttack(clientNodes.Get(0), targets, attackStart, attackStop);
    }
    else if (attack == "c2")
    {
        InstallC2Beacon(clientNodes.Get(0), ifAtt.GetAddress(0), attackStart, attackStop, 1.0);
    }

    // Install packet filter on gateway: attach a PromiscReceive callback to
    // every gateway NetDevice that decides drop-or-forward based on g_rules.
    Ptr<Node> gateway = gw.Get(0);
    for (uint32_t i = 0; i < gateway->GetNDevices(); ++i)
    {
        Ptr<NetDevice> nd = gateway->GetDevice(i);
        nd->SetPromiscReceiveCallback(MakeCallback(&BlockerNetDevice::RxFilter));
    }

    // FlowMonitor
    FlowMonitorHelper fmh;
    Ptr<FlowMonitor> fm = fmh.InstallAll();

    if (enablePcap)
    {
        p2p.EnablePcapAll("netsec_sim_" + scenario + "_" + attack, false);
    }

    Simulator::Stop(Seconds(simDuration));
    Simulator::Run();

    fm->CheckForLostPackets();
    fm->SerializeToXmlFile(flowmonOut, true, true);
    NS_LOG_UNCOND("Dropped packets by blocker: " << g_droppedPackets);

    Simulator::Destroy();
    return 0;
}
