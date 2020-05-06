

/*
IAV Network State Model
*/


/*
   attacker is at the customer edge or internet 
   pe1 is CRS with vuln CVE-2012-1342 (BGP overflow remote code execution)
   target is core router p3 control plane code execution

_c control plane interface
_d data plane interface
_m management interface
*/
attackerLocated(ce1).
attackGoal(execCode(p3_c, _)).

/*
Customer Edge devices attach to Provider Edges
control plane to exchange routing tables/VRFs
through BGP
*/
/* BGP b/t customer and provider edge */
/* update 20160425: data and control from customer on same PE port */
hacl(ce1, pe1_c,  tcp, 179).
hacl(ce1, pe1_d,  _, _). 

/* 
Customer data flows through PE data plane on predefined label switched path (MPLS tunnel)
*/

/*
Provider Edge devices talk to other PEs
BGP b/t provider edges control plane to
exchange client VRFs for tunnel endpoints 
*/
hacl(pe1_c, pe2_c,  TCP, 179).
hacl(pe1_c, pe4_c, TCP, 179).
hacl(pe2_c, pe3_c, TCP, 179).
hacl(pe2_c, pe1_c, TCP, 179).
hacl(pe3_c, pe4_c,  TCP, 179).
hacl(pe3_c, pe2_c,  TCP, 179).
hacl(pe4_c, pe1_c,  TCP, 179).
/*hacl(pe4_c, pe3_c,  TCP, 179). handle Cycles*/

/*
PEs also talk to neighbor P nodes over LDP 
*/
hacl(pe1_c, p1_c,  TCP, 646).
hacl(pe2_c, p1_c, TCP, 646).
hacl(pe3_c, p3_c,  TCP, 646).
hacl(pe4_c, p3_c,  TCP, 646).

/* 
allow PEs to speak BGP with Aggregation P's 
(this is to give us an attack path on the control plane, 
other wise no path would exist)
 */
hacl(pe1_c, p1_c,  TCP, 179).
hacl(pe2_c, p1_c, TCP, 179).
hacl(pe3_c, p3_c, TCP, 179).
hacl(pe4_c, p3_c,  TCP, 179).
/* 
hacl(pe1_c, p1_c,  TCP, 179).
hacl(pe2_c, p1_c, TCP, 179).
hacl(p1_c, pe1_c,  TCP, 179).
hacl(p1_c, pe1_c, TCP, 179).
hacl(p3_c, pe3_c, TCP, 179).
hacl(p3_c, pe4_c,  TCP, 179).
hacl(pe3_c, p3_c, TCP, 179).
hacl(pe4_c, p3_c,  TCP, 179).
*/

/*
Core P nodes speak LDP to each other to establish LSPs
The VPN tunnel over an LSP can be configured statically or dynamically with TE bindings.
We assume static for now. 
*/
/* allow control messages through LDP */
hacl(p1_c, p2_c,  TCP, 646).
hacl(p1_c, p4_c, TCP, 646).
hacl(p1_c, p3_c, TCP, 646).
hacl(p2_c, p3_c,  TCP, 646).
hacl(p4_c, p3_c,  TCP, 646).

/* 
assume our LSP tunnel is configured:
PE1 -> P1 -> P3 -> PE3
data flow is one way (another tunnel needed for return traffic)
 */
hacl(pe1_d, p1_d,  _, _).
hacl(p1_d, p3_d, _, _).
hacl(p3_d, pe3_d, _, _).

/* 
P's don't speak BGP to other Ps
(although OSPF might be used for neighbor/LDP exchange)
*/
/*
hacl(p1_c, p2_c, TCP, 179).
hacl(p1_c, p4_c, TCP, 179).
hacl(p2_c, p3_c,  TCP, 179).
hacl(p4_c, p3_c,  TCP, 179).
*/


/*
Management Plane interfaces allow SSH, Telnet, SNMP, NTP
to all network elements
just adding SSH for now to avoid clutter 
(can't separate multiple ports with | )
*/
/* 
hacl(pe1_m, _,  tcp, 22).
hacl(pe2_m, _,  tcp, 22).
hacl(pe3_m, _,  tcp, 22).
hacl(pe3_m, _,  tcp, 22).
hacl(p1_m, _,  tcp, 22).
hacl(p2_m, _,  tcp, 22).
hacl(p3_m, _,  tcp, 22).
hacl(p4_m, _,  tcp, 22).
*/

/*
hacl(H, H, _, _).
*/


/*
Vulnerability Definitions
*/
/* 
PE's can be:
Cisco 12000 (IOS v12)
Cisco ASR 9000 (IOS XR 4.1)
Cisco CRS1 (IOS XR 4.3)
*/

/* BGP exploit lets attacker escalate privilege on attached PE's control interface */
vulExists(pe1_c, 'CVE-2012-1342', bgp).
vulExists(pe1_d, 'CVE-2012-1342', _). /* CE ingress control/data same port */
vulExists(pe2_c, 'CVE-2012-1342', bgp).
vulExists(pe3_c, 'CVE-2012-1342', bgp).
vulExists(pe4_c, 'CVE-2012-1342', bgp).
vulExists(p1_c, 'CVE-2012-1342', bgp).
vulExists(p3_c, 'CVE-2012-1342', bgp).
vulProperty( 'CVE-2012-1342', remoteExploit, privEscalation).
networkServiceInfo(pe1_c , bgp, TCP, 179, root).
networkServiceInfo(pe2_c , bgp, TCP, 179, root).
networkServiceInfo(pe3_c , bgp, TCP, 179, root).
networkServiceInfo(pe4_c , bgp, TCP, 179, root).
networkServiceInfo(p1_c , bgp, TCP, 179, root).
networkServiceInfo(p3_c , bgp, TCP, 179, root).

/* 
Even if the P nodes have the same vulnerabilities as the current architecture,
address space isolation prevents attackers from directly addressing these elements.
*/
vulExists(p1_d, 'CVE-2007-5381', rsvp).
vulExists(p2_d, 'CVE-2007-5381', rsvp).
vulExists(p3_d, 'CVE-2007-5381', rsvp).
vulExists(p4_d, 'CVE-2007-5381', rsvp).
vulProperty( 'CVE-2007-5381', remoteExploit, privEscalation).
/*
networkServiceInfo(p3_d , rsvp, TCP, 3455, root).
networkServiceInfo(p1_d , _, _, _, _).
networkServiceInfo(p2_d , _, _, _, _).
networkServiceInfo(p4_d , _, _, _, _).
hacl(p3_d, p3_c,  _, _). */ /*this is the result of the exploit */


/* Remote code execution allows attacker to move from control -> management plane */
/*
vulExists(pe2_m, 'CVE-2007-5381', _).
vulProperty( 'CVE-2007-5381', remoteExploit, privEscalation).
networkServiceInfo(pe2_m , _, _, _, _).

vulExists(pe3_c, 'CVE-2011-4012', _).
vulProperty( 'CVE-2011-4012', remoteExploit, privEscalation).
networkServiceInfo(pe3_c , bgp, tcp, 179, root).

vulExists(pe4_c, 'CVE-2015-0694', _).
vulProperty( 'CVE-2015-0694', remoteExploit, privEscalation).
networkServiceInfo(pe4_c , _, _, _, _).
*/

/*  
P's can be:
Cisco CRS1 (IOS XR 4.3)
*/

/*
Assuming aggregation (P1,P3) run BGP but core (P2,P4) don't
This gives a common attack path between the 3 models,
otherwise IAV would have no attack paths (we could introduce another PE->Aggregation vuln)
*/
vulExists(p1_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p1_c , bgp, TCP, 179, root).
vulExists(p3_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p3_c ,  bgp, TCP, 179, root).
/*
vulExists(p2_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p2_c , _, _, _, _).
vulExists(p4_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p4_c , bgp, TCP, 179, root).
*/

/*  
RR's can be:
Juniper M320 (JunOS 13.2)
Can add these between sites/AS's if vulnerabilities are identified
*/
