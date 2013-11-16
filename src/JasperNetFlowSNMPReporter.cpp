#include "JasperNetFlowSNMPReporter.h"

JasperNetFlowSNMPReporter::JasperNetFlowSNMPReporter()
	: MibLeaf("1.3.6.1.3.100.2.1.0", READONLY, new SnmpInt32(0))
{
}

void JasperNetFlowSNMPReporter::get_request(Request* req, int ind)
{
	*((SnmpInt32*)value) = 42; // main life question
	MibLeaf::get_request(req, ind);
}

