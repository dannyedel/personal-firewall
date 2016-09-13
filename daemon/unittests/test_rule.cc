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

	Packet p{ facts };
	Rule r{ match, Verdict::accept };

	BOOST_CHECK_THROW( r.matches(p), NeedDnsResolve);
}

BOOST_AUTO_TEST_CASE(simpleMatch) {
	/** Tests whether a simple ruleset matches itself.
	 *
	 * This should always be true.
	 */

	ptree facts;
	facts.put("sourceaddress", "10.1.2.3");
	facts.put("sourceport", "80");
	facts.put("layer4protocol", "tcp");

	Packet p{ facts };
	Rule r{ facts, Verdict::accept };

	BOOST_CHECK( r.matches(p) );
}

BOOST_AUTO_TEST_CASE(wildcardMatch) {
	ptree metadata;
	metadata.put("hostnamelookupdone", "true");
	{
		ptree facts;
		facts.put("sourcehostname", "somehost.example.org");
		Packet p{ facts, metadata };

		ptree factsdest;
		factsdest.put("destinationhostname", "somehost.example.org");
		Packet pdest{ factsdest, metadata };

		ptree facts2;
		facts2.put("sourcehostname", "somehost.example.com");
		Packet p2{ facts2, metadata };

		{
			ptree match;
			match.put("hostnamematch", "*.example.org");

			Rule r{ match , Verdict::accept };

			BOOST_CHECK( r.matches(p) );
			BOOST_CHECK( r.matches(pdest) );
			BOOST_CHECK( ! r.matches(p2) );
		}

		{
			ptree match2;
			match2.put("sourcehostnamematch", "*.example.org");
			Rule rule2{ match2, Verdict::accept};

			BOOST_CHECK( rule2.matches(p) );
			BOOST_CHECK( !rule2.matches(p2) );
			BOOST_CHECK( !rule2.matches(pdest) );
		}

		{
			/** Example on how to match domain and subdomains */
			ptree facts_meeo;
			facts_meeo.put("sourcehostname", "me.example.org");
			Packet p_meeo{facts_meeo, metadata};

			ptree facts_eo;
			facts_eo.put("sourcehostname", "example.org");
			Packet p_eo{facts_eo, metadata};

			ptree facts_noteo;
			facts_noteo.put("sourcehostname", "attacker.not-example.org");
			Packet p_noteo{facts_noteo, metadata};

			ptree facts_ecom;
			facts_ecom.put("sourcehostname", "example.com");
			Packet p_ecom{facts_ecom, metadata};

			// Example of a bad written rule
			ptree match_bad;
			match_bad.put("sourcehostnamematch", "*example.org");
			Rule rule_bad{match_bad, Verdict::accept};

			// This rule will match example.org, me.example.org,
			// but also the attacker
			BOOST_CHECK( rule_bad.matches(p_eo) );
			BOOST_CHECK( rule_bad.matches(p_meeo) );
			BOOST_CHECK( rule_bad.matches(p_noteo) ); // this is bad
			BOOST_CHECK( !rule_bad.matches(p_ecom) ); // as intended

			// Better written rule
			ptree match_good;
			match_good.put("sourcehostnamematch", "?(*.)example.org");
			Rule rule_good{match_good, Verdict::accept};

			BOOST_CHECK( rule_good.matches(p_eo) );
			BOOST_CHECK( rule_good.matches(p_meeo) );
			BOOST_CHECK( ! rule_good.matches(p_noteo) ); // aha!
			BOOST_CHECK( ! rule_good.matches(p_ecom) );
		}

		{
			ptree match3;
			match3.put("destinationhostnamematch", "*.example.org");
			Rule rule3{ match3, Verdict::accept};

			BOOST_CHECK( !rule3.matches(p) );
			BOOST_CHECK( rule3.matches(pdest) );
			BOOST_CHECK( !rule3.matches(p2) );
		}
	}

	{
		ptree facts;
		facts.put("destinationhostname", "somehost1234.cool-subdomain.example.org");
		Packet p { facts, metadata};

		ptree match;
		match.put("hostnamematch", "*.cool-subdomain.example.org");
		Rule r{ match, Verdict::accept };

		BOOST_CHECK( r.matches(p) );
	}
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

	Packet p1{ facts1 };
	Packet p2{ facts2 };

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

	Packet p{ facts };

	Rule r1{ match1, Verdict::accept};
	Rule r2{ match2, Verdict::accept};
	Rule r3{ match3, Verdict::accept};

	BOOST_CHECK_EQUAL(false, r1.matches(p));
	BOOST_CHECK_EQUAL(false, r1.matches(p));
	BOOST_CHECK_EQUAL(false, r3.matches(p));
}

BOOST_AUTO_TEST_CASE(testInvalidKey) {
	ptree match;
	match.put("somerandomkey", "thisShouldNotWork");

	BOOST_CHECK_THROW( Rule r(match, Verdict::accept), InvalidKey);
}

BOOST_AUTO_TEST_CASE(constructFromFile) {
	Rule fromfile( "rules/01_accept_from_b" );

	ptree pt;
	pt.put("hostname", "b");
	Rule direct( pt, Verdict::accept);

	BOOST_CHECK_EQUAL(fromfile, direct);
}

BOOST_AUTO_TEST_CASE(throwOnInvalidFile) {

	BOOST_CHECK_THROW(Rule("invalid-rules/invalidverdict"), InvalidRuleFile);

	BOOST_CHECK_THROW(Rule("invalid-rules/invalidtree"), InvalidRuleFile);

	BOOST_CHECK_THROW(Rule("invalid-rules/invalidkey"), InvalidRuleFile);

	BOOST_CHECK_THROW(Rule("invalid-rules/emptyfile"), InvalidRuleFile);
}

BOOST_AUTO_TEST_SUITE_END();
