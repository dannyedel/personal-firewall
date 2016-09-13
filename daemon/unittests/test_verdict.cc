#include <verdict.hh>

#include <boost/test/unit_test.hpp>
#include <boost/lexical_cast.hpp>
#include <string>

using boost::lexical_cast;
using namespace PersonalFirewall;
using namespace std;

BOOST_AUTO_TEST_SUITE(verdict)

BOOST_AUTO_TEST_CASE(castToString) {
	BOOST_CHECK_EQUAL("undecided", lexical_cast<string>(Verdict::undecided));
	BOOST_CHECK_EQUAL("accept", lexical_cast<string>(Verdict::accept));
	BOOST_CHECK_EQUAL("reject", lexical_cast<string>(Verdict::reject));
}

BOOST_AUTO_TEST_CASE(castFromString) {
	BOOST_CHECK_EQUAL(Verdict::undecided, lexical_cast<Verdict>("undecided"));
	BOOST_CHECK_EQUAL(Verdict::accept, lexical_cast<Verdict>("accept"));
	BOOST_CHECK_EQUAL(Verdict::reject, lexical_cast<Verdict>("reject"));

	BOOST_CHECK_THROW(lexical_cast<Verdict>("other"), boost::bad_lexical_cast);
}

BOOST_AUTO_TEST_SUITE_END()
