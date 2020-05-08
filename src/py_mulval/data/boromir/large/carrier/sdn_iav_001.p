

/*
Future Network State Model
*/


/*
   attacker is at the internet 
   pe1 is CRS with vuln CVE-2012-1342 (ACL bypass)
   target is core router p2 control plane code execution

_c control plane interface
_d data plane interface
_m management interface
*/
attackerLocated(ce1).
attackGoal(execCode(p3_c, _)).

/*
Customer Edge devices attach to Provider Edges
control plane to exchange routing tables/VRFs
through BGP or maybe RIP,...
*/
/* BGP b/t customer and provider edge */
hacl(ce1, pe1_c,  tcp, 179). 

/*
hacl(ce1_2, pe1_c, tcp, 179).
hacl(ce2, pe2_c,  tcp, 179).
hacl(ce3, pe3_c,  tcp, 179). 
hacl(ce4, pe4_c, tcp, 179). 
*/

/* Customer data flows pass through PE data plane
on any port/protocol '_'
*/
hacl(ce1, pe1_d,  _, _). 
/*
hacl(ce1_2, pe1_d, _, _).
hacl(ce2, pe2_d,  _, _).
hacl(ce3, pe3_d,  _, _). 
hacl(ce4, pe4_d, _, _). 
*/

/* ???
Provider Edge devices pass data through other PE's?
*/
/*Customer data flows pass through PE data plane
on any port/protocol '_' */
hacl(pe1_d, pe2_d, _ , _).
hacl(pe1_d, pe4_d, _ , _).
hacl(pe2_d, pe3_d, _ , _).
hacl(pe3_d, pe4_d, _ , _).


/*
Provider Edge devices no longer speak to other PEs
instead they communicate route info with SDN (local or global?)
*/
/* BGP b/t provider edges control plane
exchange client VRFs for tunnel endpoints */
/*
hacl(pe1_c, pe2_c,  tcp, 179).
hacl(pe1_c, pe4_c, tcp, 179).
hacl(pe2_c, pe3_c, tcp, 179).
hacl(pe3_c, pe4_c,  tcp, 179).
*/
hacl(pe1_c, sdn,  tcp, 179).
hacl(pe1_c, sdn, tcp, 179).
hacl(pe2_c, sdn, tcp, 179).
hacl(pe3_c, sdn,  tcp, 179).


/*
PEs also talk to core P nodes
*/
/* allow all protocols and ports on dataplane with _ */
hacl(pe1_d, p1_d,  _, _).
hacl(pe2_d, p1_d,  _, _).
hacl(pe3_d, p3_d,  _, _).
hacl(pe4_d, p3_d,  _, _).

/* allow PEs to exchange LDP, RSVP, PIM/TWAMP with P's 
just adding LDP for now to avoid clutter 
(can't separate multiple ports with | */
/*
hacl(pe1_c, p1_c,  TCP, 646).
hacl(pe2_c, p1_c, TCP, 646).
hacl(pe3_c, p3_c, TCP, 646).
hacl(pe4_c, p3_c,  TCP, 646).
*/
/* PEs no longer use distributed protocols for link state, label 
distribution, reservations, ... instead are pushed configs and send 
state info to SDN on 6633
*/
hacl(pe1_c, sdn, tcp, 6633).
hacl(pe2_c, sdn, tcp, 6633).
hacl(pe3_c, sdn, tcp, 6633).
hacl(pe4_c, sdn, tcp, 6633).

/*
Core P nodes can talk to each other
*/
/* allow data flows through any port/protocol */
hacl(p1_d, p2_d,  _, _).
hacl(p2_d, p3_d,  _, _).

/* allow Ps to exchange LDP, RSVP, PIM/TWAMP with P's 
just adding LDP for now to avoid clutter 
(can't separate multiple ports with | )*/
/*
hacl(p1_c, p2_c, TCP, 646).
hacl(p2_c, p3_c,  TCP, 646).
*/
/* P nodes only communicate info with SDN */
hacl(p1_c, sdn, TCP, 6633).
hacl(p2_c, sdn,  TCP, 6633).


/*
Management Plane interfaces allow SSH, Telnet, SNMP, NTP
to all network elements
just adding SSH for now to avoid clutter 
(can't separate multiple ports with | )
*/
hacl(pe1_m, _,  tcp, 22).
hacl(pe2_m, _,  tcp, 22).
hacl(pe3_m, _,  tcp, 22).
hacl(pe3_m, _,  tcp, 22).
hacl(p1_m, _,  tcp, 22).
hacl(p2_m, _,  tcp, 22).
hacl(p3_m, _,  tcp, 22).

/*
hacl(H, H, _, _).
*/
hacl(sdn, pe1_c,  tcp, 6633).
hacl(sdn, pe2_c,  tcp, 6633).
hacl(sdn, pe3_c,  tcp, 6633).
hacl(sdn, pe4_c,  tcp, 6633).
hacl(sdn, p1_c,  tcp, 6633).
hacl(sdn, p2_c,  tcp, 6633).
hacl(sdn, p3_c,  tcp, 6633).


/* 
SDN controller can communicate with all network devices
over tcp 6633 and push configs that effictively give it
root access on the device
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

/* keep all these the same as curr */
/* ACL Bypass let's attacker move from data plane to control plane */
vulExists(pe1_c, 'CVE-2012-1342', bgp).
vulProperty( 'CVE-2012-1342', remoteExploit, privEscalation).
networkServiceInfo(pe1_c , bgp, tcp, 179, root).

/* Remote code execution allows attacker to move from control -> management plane */
vulExists(pe2_m, 'CVE-2007-5381', _).
vulProperty( 'CVE-2007-5381', remoteExploit, privEscalation).
networkServiceInfo(pe2_m , _, _, _, _).

vulExists(pe3_c, 'CVE-2011-4012', _).
vulProperty( 'CVE-2011-4012', remoteExploit, privEscalation).
networkServiceInfo(pe3_c , bgp, tcp, 179, root).

vulExists(pe4_c, 'CVE-2015-0694', _).
vulProperty( 'CVE-2015-0694', remoteExploit, privEscalation).
networkServiceInfo(pe4_c , _, _, _, _).

/*  
P's can be:
Cisco CRS1 (IOS XR 4.3)
*/

vulExists(p1_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p1_c , ldp, tcp, 646, root).

vulExists(p2_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p2_c , _, _, _, _).

vulExists(p3_c, 'CVE-2009-2048',xss).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p3_c , _, _, _, _).

/*  
RR's can be:
Juniper M320 (JunOS 13.2)

Not sure where to put this yet
*/


/* 
SDN (OpenDaylight) vulnerabilities are documented at
https://wiki.opendaylight.org/view/Security_Advisories
CVE-2014-5035 - is the only one documented in the NVD DB (XXE info disclosure)

however for our purposes we assume CVE-2015-7501 (remote code execution -> critical (cvss 2.5)
is open and reachable through 6633 
*/
vulExists(sdn, 'CVE-2015-7501',_).
vulProperty('CVE-2015-7501', remoteExploit, privEscalation).
networkServiceInfo(sdn , _, _, 6633, root).