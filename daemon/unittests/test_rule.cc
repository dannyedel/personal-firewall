#include <rule.hh>
#include <boost/test/unit_test.hpp>

using namespace PersonalFirewall;
using boost::property_tree::ptree;

BOOST_AUTO_TEST_SUITE(rule)

BOOST_AUTO_TEST_CASE(throwOnDns) {

	ptree match;
	match.put("sourcehostname", "resolveme");

	ptree facts;
	facts.put("sourceaddress", "10.1.1.1");
	facts.put("destinationaddress", "10.2.2.2");

	Packet p{ facts, ptree(), Verdict::undecided };
	Rule r{ match, Verdict::accept };

	BOOST_CHECK_THROW( r.matches(p), NeedDnsResolve);
}

BOOST_AUTO_TEST_CASE(addressMatchesSrcOrDest) {

	ptree match;
	match.put("address", "10.1.1.1");

	ptree facts1;
	facts1.put("sourceaddress", "10.1.1.1");
	facts1.put("destinationaddress", "10.2.2.2");

	ptree facts2;
	facts2.put("sourceaddress", "10.2.2.2");
	facts2.put("destinationaddress", "10.1.1.1");

	Packet p1{ facts1, ptree(), Verdict::undecided };
	Packet p2{ facts2, ptree(), Verdict::undecided };

	Rule r{ match, Verdict::accept };

	BOOST_CHECK( r.matches(p1) );
	BOOST_CHECK( r.matches(p2) );
}

BOOST_AUTO_TEST_CASE(testNoMatch) {

	ptree match1;
	match1.put("address", "10.3.3.3");

	ptree match2;
	match2.put("sourceaddress", "10.3.3.3");
	
	ptree match3;
	match3.put("destinationaddress", "10.3.3.3");

	ptree facts;
	facts.put("sourceaddress", "10.1.1.1");
	facts.put("destinationaddress", "10.2.2.2");

	Packet p{ facts, ptree(), Verdict::undecided };

	Rule r1{ match1, Verdict::accept};
	Rule r2{ match2, Verdict::accept};
	Rule r3{ match3, Verdict::accept};

	BOOST_CHECK_EQUAL(false, r1.matches(p));
	BOOST_CHECK_EQUAL(false, r1.matches(p));
	BOOST_CHECK_EQUAL(false, r3.matches(p));
}

BOOST_AUTO_TEST_SUITE_END();
