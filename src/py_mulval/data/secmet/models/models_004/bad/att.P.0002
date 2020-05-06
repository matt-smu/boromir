

/*

*/


/*
   attacker is at the internet 
   pe1 is CRS with vuln CVE-2012-1342 (ACL bypass)
   target is core router p2 
*/
attackerLocated(ce1).
attackGoal(execCode(p3, _)).

/*
Customer Edge devices attach to Provider Edges
*/
hacl(ce1, pe1,  _, _).
hacl(ce1_2, pe1,  _, _).
hacl(ce2, pe2,  _, _).
hacl(ce3, pe3,  _, _).
hacl(ce4, pe4,  _, _).

/*
Provider Edge devices talk to other PEs
*/
hacl(pe1, pe2,  _, _).
hacl(pe1, pe4,  _, _).
hacl(pe2, pe3,  _, _).
hacl(pe3, pe4,  _, _).

/*
PEs also to to core P nodes
*/
hacl(pe1, p1,  _, _).
hacl(pe2, p1,  _, _).
hacl(pe3, p3,  _, _).
hacl(pe4, p3,  _, _).

/*
Core P nodes can talk to each other
*/
hacl(p1, p2,  _, _).
hacl(p2, p3,  _, _).

/*
hacl(H, H, _, _).
*/

/* 
All PEs are CRS-1's with an ACL bypass allowing remote privEscalation
*/
vulExists(pe1, 'CVE-2012-1342', _).
vulProperty( 'CVE-2012-1342', remoteExploit, privEscalation).
networkServiceInfo(pe1 , _, _, _, _).

vulExists(pe2, 'CVE-2012-1342', _).
vulProperty( 'CVE-2012-1342', remoteExploit, privEscalation).
networkServiceInfo(pe2 , _, _, _, _).

vulExists(pe3, 'CVE-2012-1342', _).
vulProperty( 'CVE-2012-1342', remoteExploit, privEscalation).
networkServiceInfo(pe3 , _, _, _, _).

vulExists(pe4, 'CVE-2012-1342', _).
vulProperty( 'CVE-2012-1342', remoteExploit, privEscalation).
networkServiceInfo(pe4 , _, _, _, _).

/* 
All Ps are CRS-1's with an XSS allowing remote code execution
*/
vulExists(p1, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p1 , _, _, _, _).

vulExists(p2, 'CVE-2009-2048',_).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p2 , _, _, _, _).

vulExists(p3, 'CVE-2009-2048',xss).
vulProperty('CVE-2009-2048', remoteExploit, privEscalation).
networkServiceInfo(p3 , _, _, _, _).


