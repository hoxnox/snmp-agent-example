#ifndef __JASPER_NETFLOW_SNMP_REPORTER_HPP__
#define __JASPER_NETFLOW_SNMP_REPORTER_HPP__

#include <agent_pp/agent++.h>
#include <agent_pp/mib.h>
#include <agent_pp/request.h>

using namespace Agentpp;

class JasperNetFlowSNMPReporter : public MibLeaf
{
public:
	JasperNetFlowSNMPReporter();
	void get_request(Agentpp::Request*, int);
};

#endif // __JASPER_NETFLOW_SNMP_REPORTER_HPP__
