#include <rulerepository.hh>
#include <boost/test/unit_test.hpp>

using namespace std;
using namespace PersonalFirewall;
using namespace boost::property_tree;

BOOST_AUTO_TEST_SUITE(rulerepository)

BOOST_AUTO_TEST_CASE(emptyreturnsdefault)
{
	vector<Verdict> testthis = {
		Verdict::accept,
		Verdict::reject,
		Verdict::undecided,
	};

	for( const auto& verdict: testthis) {
		RuleRepository rr( verdict );
		ptree tree;
		tree.put("packetid", 1);
		Packet p{ tree };
		BOOST_CHECK_EQUAL( verdict, rr.processPacket(p) );
	}

}

BOOST_AUTO_TEST_CASE(orderpreserve)
{
	ptree t1;
	t1.put("hostname", "b");
	Rule r1{t1, Verdict::accept};

	ptree t2;
	t2.put("hostname", "a");
	Rule r2{t2, Verdict::accept};

	// Assert the rules are not equal
	BOOST_CHECK_NE(r1, r2);

	// Check that the insertion order matters
	RuleRepository rr(Verdict::undecided);

	// append copies, instead of moving
	rr.append_rule(Rule(r1));
	rr.append_rule(Rule(r2));

	BOOST_CHECK_EQUAL(r1, rr.rules().at(0));

	BOOST_CHECK_EQUAL(r2, rr.rules().at(1));
}

BOOST_AUTO_TEST_CASE(loadfromdirectory)
{
	// These are the files in the directory
	// Verify that loading them results in
	// identical rules
	ptree t1;
	t1.put("hostname", "b");
	Rule r1{t1, Verdict::accept};

	ptree t2;
	t2.put("hostname", "a");
	Rule r2{t2, Verdict::reject};

	RuleRepository rr(Verdict::undecided, "rules/");

	BOOST_CHECK_EQUAL(r1, rr.rules().at(0));
	BOOST_CHECK_EQUAL(r2, rr.rules().at(1));
}

BOOST_AUTO_TEST_SUITE_END();
