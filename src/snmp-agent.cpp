#include <stdlib.h>
#include <signal.h>

#include <agent_pp/agent++.h>
#include <agent_pp/snmp_group.h>
#include <agent_pp/system_group.h>
#include <agent_pp/snmp_target_mib.h>
#include <agent_pp/snmp_notification_mib.h>
#include <agent_pp/notification_originator.h>
#include <agent_pp/mib_complex_entry.h>
#include <agent_pp/v3_mib.h>
#include <agent_pp/vacm.h>

#include <snmp_pp/oid_def.h>
#include <snmp_pp/mp_v3.h>
#include <snmp_pp/log.h>

#include <iostream>

#include <JasperNetFlowSNMPReporter.h>

#ifdef SNMP_PP_NAMESPACE
using namespace Snmp_pp;
#endif

#ifdef AGENTPP_NAMESPACE
using namespace Agentpp;
#endif

void init(Mib& mib)
{
	/* This agent can do more !
	mib.add(new snmpGroup());
	mib.add(new snmp_target_mib());
	mib.add(new snmp_notification_mib());
	*/
	mib.add(new JasperNetFlowSNMPReporter());
#ifdef _SNMPv3
	UsmUserTable *uut = new UsmUserTable();
	uut->addNewRow("unsecureUser",
	               SNMP_AUTHPROTOCOL_NONE,
	               SNMP_PRIVPROTOCOL_NONE, "", "");
	uut->addNewRow("MD5",
	               SNMP_AUTHPROTOCOL_HMACMD5,
	               SNMP_PRIVPROTOCOL_NONE,
	               "MD5UserAuthPassword", "");
	// add non persistent USM statistics
	mib.add(new UsmStats());
	// add the USM MIB - usm_mib MibGroup is used to
	// make user added entries persistent
	mib.add(new usm_mib(uut));
	// add non persistent SNMPv3 engine object
	mib.add(new V3SnmpEngine());
#endif
}

int main (int argc, char* argv[])
{

	unsigned short port = 4160;
	Mib mib;
	RequestList reqList;

	int status;
	Snmp::socket_startup();  // Initialize socket subsystem
	Snmpx snmp(status, port);
	if (status != SNMP_CLASS_SUCCESS)
	{
		std::cerr << "SNMP init failed" << std::endl;
		return 1;
	}

#ifdef _SNMPv3
	unsigned int snmpEngineBoots = 0;
	OctetStr engineId(SnmpEngineID::create_engine_id(port));
	status = mib.get_boot_counter(engineId, snmpEngineBoots);
	if ((status != SNMPv3_OK) && (status < SNMPv3_FILEOPEN_ERROR))
	{
		std::cerr << "Error loading snmpEngineBoots counter";
		return 1;
	}
	snmpEngineBoots++;
	status = mib.set_boot_counter(engineId, snmpEngineBoots);
	if (status != SNMPv3_OK)
	{
		std::cerr << "Error saving snmpEngineBoots counter";
		return 1;
	}
	v3MP v3mp(engineId, snmpEngineBoots, status);
	reqList.set_v3mp(&v3mp);
#endif

	// register requestList for outgoing requests
	mib.set_request_list(&reqList);
	// add supported objects
	init(mib);
	// load persitent objects from disk
	mib.init();
	reqList.set_snmp(&snmp);

#ifdef _SNMPv3
	// register VACM
	Vacm vacm(mib);
	reqList.set_vacm(&vacm);

	// initialize security information
	vacm.addNewContext("");
	vacm.addNewContext("other");

	// Add new entries to the SecurityToGroupTable.
	// Used to determine the group a given SecurityName belongs to.
	// User "new" of the USM belongs to newGroup

	vacm.addNewGroup(SNMP_SECURITY_MODEL_V2, "public",
	                 "v1v2group", storageType_volatile);
	vacm.addNewGroup(SNMP_SECURITY_MODEL_V1, "public",
	                 "v1v2group", storageType_volatile);
	vacm.addNewGroup(SNMP_SECURITY_MODEL_USM, "unsecureUser",
	                 "newGroup", storageType_volatile);
	vacm.addNewGroup(SNMP_SECURITY_MODEL_USM, "MD5",
	                 "testNoPrivGroup", storageType_volatile);
	vacm.addNewGroup(SNMP_SECURITY_MODEL_USM, "SHA",
                         "testNoPrivGroup", storageType_volatile);


	// Set access rights of groups.
	// The group "newGroup" (when using the USM with a security
	// level >= noAuthNoPriv within context "") would have full access
	// (read, write, notify) to all objects in view "newView".
	vacm.addNewAccessEntry("newGroup",
	                        "other",        // context
	                        SNMP_SECURITY_MODEL_USM,
	                        SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV,
	                        match_exact,  // context must mach exactly
	                        // alternatively: match_prefix
	                        "newView", // readView
	                        "newView", // writeView
	                        "newView", // notifyView
	                        storageType_nonVolatile);
	vacm.addNewAccessEntry("testNoPrivGroup", "",
	                        SNMP_SECURITY_MODEL_USM,
	                        SNMP_SECURITY_LEVEL_AUTH_NOPRIV,
	                        match_prefix,
	                        "testView", "testView",
	                        "testView", storageType_nonVolatile);
	vacm.addNewAccessEntry("v1v2group", "",
	                        SNMP_SECURITY_MODEL_V2,
	                        SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV,
	                        match_exact,
	                        "v1ReadView", "v1WriteView",
	                        "v1NotifyView", storageType_nonVolatile);
	vacm.addNewAccessEntry("v1v2group", "",
	                        SNMP_SECURITY_MODEL_V1,
	                        SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV,
	                        match_exact,
	                        "v1ReadView", "v1WriteView",
	                        "v1NotifyView", storageType_nonVolatile);

	// Defining Views
	// View "v1ReadView" includes all objects starting with "1.3".
	// If the ith bit of the mask is not set (0), then also all objects
	// which have a different subid at position i are included in the
	// view.
	// For example: Oid "6.5.4.3.2.1", Mask(binary) 110111
	//              Then all objects with Oid with "6.5.<?>.3.2.1"
	//              are included in the view, whereas <?> may be any
	//              natural number.

	vacm.addNewView("v1ReadView",
	                "1.3",
	                "",             // Mask "" is same as 0xFFFFFFFFFF...
	                view_included,  // alternatively: view_excluded
	                storageType_nonVolatile);

	vacm.addNewView("v1WriteView",
	                "1.3",
	                "",             // Mask "" is same as 0xFFFFFFFFFF...
	                view_included,  // alternatively: view_excluded
	                storageType_nonVolatile);

	vacm.addNewView("v1NotifyView",
	                "1.3",
	                "",             // Mask "" is same as 0xFFFFFFFFFF...
	                view_included,  // alternatively: view_excluded
	                storageType_nonVolatile);

	vacm.addNewView("newView", "1.3", "",
	                view_included, storageType_nonVolatile);
	vacm.addNewView("testView", "1.3.6", "",
	                view_included, storageType_nonVolatile);
#endif

	Request* req;
	while (true)
	{
		req = reqList.receive(2);
		if (req)
		{
			mib.process_request(req);
		}
		else
		{
			mib.cleanup();
		}
	}
	Snmp::socket_cleanup();  // Shut down socket subsystem
	return 0;
}

