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
		RuleRepository rr( verdict, "/dev/null");
		ptree tree;
		tree.put("packetid", 1);
		Packet p{ tree };
		BOOST_CHECK_EQUAL( verdict, rr.processPacket(p) );
	}

}

BOOST_AUTO_TEST_SUITE_END();
