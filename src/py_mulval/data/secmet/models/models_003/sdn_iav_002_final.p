

/*
SDN IAV Network State Model
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
Customer data flows through PE data plane on SDN controlled label switched path (MPLS tunnel)
*/

/*
Provider Edge devices speak BGP to the SDN controller to 
exchange customer VRFs
*/
hacl(pe1_c, sdn,  TCP, 179).
hacl(pe2_c, sdn, TCP, 179).
hacl(pe3_c, sdn,  TCP, 179).
hacl(pe4_c, sdn,  TCP, 179).

/*
PE (LER) and P (LSR) nodes speak LDP to the SDN controller 
who in turn determines neighbors and sets up LSPs.
SDN also defines VPN tunnel endpoints and paths. 
*/
hacl(pe1_c, sdn,  TCP, 646).
hacl(pe2_c, sdn, TCP, 646).
hacl(pe3_c, sdn,  TCP, 646).
hacl(pe4_c, sdn,  TCP, 646).
hacl(p1_c, sdn,  TCP, 646).
hacl(p2_c, sdn, TCP, 646).
hacl(p3_c, sdn,  TCP, 646).
hacl(p4_c, sdn,  TCP, 646).

/* 
Flow rules and other SDN control signaling goes over OpenFlow (port 6633)
Juniper Contrail would use XMPP or other TCP type protocol. We assume sdn global ECOMP for now
*/
hacl(pe1_c, sdn, tcp, 6633).
hacl(pe2_c, sdn, tcp, 6633).
hacl(pe3_c, sdn, tcp, 6633).
hacl(pe4_c, sdn, tcp, 6633).
hacl(p1_c, sdn, tcp, 6633).
hacl(p2_c, sdn, tcp, 6633).
hacl(p3_c, sdn, tcp, 6633).
hacl(p4_c, sdn, tcp, 6633).

/* 
assume our LSP tunnel is configured:
PE1 -> P1 -> P3 -> PE3
data flow is one way (another tunnel needed for return traffic)
 */
hacl(pe1_d, p1_d,  _, _).
hacl(p1_d, p3_d, _, _).
hacl(p3_d, pe3_d, _, _).


/*
Management Plane interfaces allow SSH, Telnet, SNMP, NTP
to all network elements
just adding SSH for now to avoid clutter 
(do these still exist with SDN?)
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
hacl(sdn, _,  _, _).


/*
Vulnerability Definitions
*/
/* 
For SDN migration we assume:
* Merchant Silicon switches, routers, OLTs... (HW Trojans? Firmware flashing? ...)
* SDN Global - ECOMP / Openflow
* SDN Local - Juniper Contrail / XMPP
* SDN Controller OS - Ubuntu 14.04 / App host
* NFV Host - RHEV 2.2, KVM 83 / Hypervisor 
* NFV Guests - PE?, RR?, TE? 
*/

/* 
SDN controller can communicate with all network devices
over tcp 6633 and push configs that effictively give it
root access on the device
*/ 

/* Assuming PE (NFV) the attacker is attached to is running on a vulnerable version
of the hypervisor allowing remote privilege escalation on the PE 
CVE-2010-2784 (cvss 6.8) is a KVM vulnerability we use to demonstrate
 */
vulExists(pe1_c, 'CVE-2010-2784', _).
vulProperty( 'CVE-2010-2784', remoteExploit, privEscalation).
networkServiceInfo(pe1_c , _, _, _, _).

/* 
SDN (OpenDaylight) vulnerabilities are documented at
https://wiki.opendaylight.org/view/Security_Advisories
CVE-2014-5035 - is the only one documented in the NVD DB (XXE info disclosure)

however for our purposes we assume CVE-2015-7501 (remote code execution -> critical (cvss 2.5)
is open and reachable through 6633. The low cvss score equates to a high difficulty in exploitation
which we would expect given the elevated access of our sdn controller.  
*/
vulExists(sdn, 'CVE-2015-7501',_).
vulProperty('CVE-2015-7501', remoteExploit, privEscalation).
networkServiceInfo(sdn , _, _, 6633, root).

/* 
If the SDN controller is rooted all network elements become reachable so no NACL/routing rules
will prevent access. We assume the SDN controller isn't able to view/modify network credentials(?)
but use a high score 9.5 (easy to exploit) vulnerability to reach the target. This is where the list 
of commodity/OTS vulnerabilities would be defined.
*/
vulExists(p3_c, 'CVE-2016-xxxx',_).
vulProperty('CVE-2016-xxxx', remoteExploit, privEscalation).
networkServiceInfo(p3_c , _, _, _, root).

