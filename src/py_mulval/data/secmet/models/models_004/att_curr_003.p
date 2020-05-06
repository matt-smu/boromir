

/*
Current Network State Model
*/


/*
   attacker is at the customer edge or internet 
   pe1 is CRS with vuln CVE-2012-1342 (ACL bypass)
   target is core router p2 control plane code execution

_c control plane interface
_d data plane interface
_m management interface
*/
attackerLocated(ce1).
attackGoal(execCode(p3_c, _)).
/*
attackGoal(execCode(p3_c, _)).
*/

/*
Customer Edge devices attach to Provider Edges
control plane to exchange routing tables/VRFs
through BGP
*/
/* BGP b/t customer and provider edge */
/* update 20160425: data and control from customer on same PE port */
hacl(ce1, pe1_c,  tcp, 179).
hacl(ce1, pe1_d,  _, _). 

/* Customer data flows pass through PE data plane
on any port/protocol '_'
*/
/* update 20160425: data and control from customer on same PE port */
/*
hacl(ce1, pe1_c,  _, _).
hacl(pe1_d, pe1_c,  _, _).
hacl(pe1_c, pe1_d,  _, _).   
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
Provider Edge devices talk to other PEs
BGP b/t provider edges control plane
exchange client VRFs for tunnel endpoints 
*/
hacl(pe1_c, pe2_c,  TCP, 179).
hacl(pe1_c, pe4_c, TCP, 179).
hacl(pe2_c, pe3_c, TCP, 179).
hacl(pe2_c, pe1_c, TCP, 179).
hacl(pe3_c, pe4_c,  TCP, 179).
hacl(pe3_c, pe2_c,  TCP, 179).
hacl(pe4_c, pe3_c,  TCP, 179).
hacl(pe4_c, pe1_c,  TCP, 179).

/*
hacl(pe1_c, pe2_c,  TCP, 179).
hacl(pe1_c, pe4_c, TCP, 179).
hacl(pe2_c, pe3_c, TCP, 179).
hacl(pe2_c, pe1_c, TCP, 179).
hacl(pe3_c, pe4_c,  TCP, 179).
hacl(pe3_c, pe2_c,  TCP, 179).
hacl(pe4_c, pe3_c,  TCP, 179).
hacl(pe4_c, pe1_c,  TCP, 179).
*/

/*
PEs also talk to core P nodes
*/
/* allow all protocols and ports on dataplane with _ */
hacl(pe1_d, p1_d,  _, _).
hacl(pe2_d, p1_d,  _, _).
hacl(pe3_d, p3_d,  _, _).
hacl(pe4_d, p3_d,  _, _).

/* 
allow PEs to speak BGP with P's 
 */
hacl(pe1_c, p1_c,  TCP, 179).
hacl(pe2_c, p1_c, TCP, 179).
hacl(pe3_c, p3_c, TCP, 179).
hacl(pe4_c, p3_c,  TCP, 179).
hacl(p1_c, pe1_c,  TCP, 179).
hacl(p2_c, pe1_c, TCP, 179).
hacl(p3_c, pe3_c, TCP, 179).
hacl(p4_c, pe3_c,  TCP, 179).
 /*
hacl(pe1_c, p1_c,  TCP, 179).
hacl(pe2_c, p1_c, TCP, 179).
hacl(pe3_c, p3_c, TCP, 179).
hacl(pe4_c, p3_c,  TCP, 179).
hacl(p1_c, pe1_c,  TCP, 179).
hacl(p2_c, pe1_c, TCP, 179).
hacl(p3_c, pe3_c, TCP, 179).
hacl(p4_c, pe3_c,  TCP, 179).
*/

/*
Core P nodes can talk to each other
*/
/* allow data flows through any port/protocol */
hacl(p1_d, p2_d,  _, _).
hacl(p1_d, p4_d,  _, _).
hacl(p1_d, p3_d,  _, _).
hacl(p2_d, p3_d,  _, _).
hacl(p4_d, p3_d,  _, _).

/* allow Ps to speak BGP with other Ps*/
hacl(p1_c, p2_c, TCP, 179).
hacl(p1_c, p4_c, TCP, 179).
hacl(p2_c, p3_c,  TCP, 179).
hacl(p4_c, p3_c,  TCP, 179).
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

/* ACL Bypass let's attacker address infrastructure directly */
vulExists(pe1_c, 'CVE-2012-1342', bgp).
vulExists(pe1_d, 'CVE-2012-1342', _).
vulProperty( 'CVE-2012-1342', remoteExploit, privEscalation).
networkServiceInfo(pe1_c , bgp, TCP, 179, root).
networkServiceInfo(pe1_d , _, _, _, root).

/* 
Any vulnerability on P3 is now reachable by attacker directly addressing that node
This example assumes an RSVP vulnerability exists in P nodes resulting in 
remote code execution that allows attacker to target control plane from data plane locally.
*/
vulExists(p1_d, 'CVE-2007-5381', rsvp).
vulExists(p2_d, 'CVE-2007-5381', rsvp).
vulExists(p3_d, 'CVE-2007-5381', rsvp).
vulExists(p4_d, 'CVE-2007-5381', rsvp).
vulProperty( 'CVE-2007-5381', remoteExploit, privEscalation).
networkServiceInfo(p3_d , rsvp, TCP, 3455, root).
networkServiceInfo(p1_d , _, _, _, _).
networkServiceInfo(p2_d , _, _, _, _).
networkServiceInfo(p4_d , _, _, _, _).
hacl(p3_d, p3_c,  _, _). /*this is the result of the exploit */


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
vulExists(p1_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p1_c , bgp, TCP, 179, root).

vulExists(p2_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p2_c , _, _, _, _).

vulExists(p3_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p3_c , _, _, _, _).

vulExists(p4_c, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p4_c , bgp, TCP, 179, root).


/*  
RR's can be:
Juniper M320 (JunOS 13.2)
Can add these between sites/AS's if vulnerabilities are identified
*/
