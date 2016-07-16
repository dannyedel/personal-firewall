#pragma once

class PersonalFirewall{
public:

private:
	/** Packets received from the kernel,
	 * to be processed */
	PacketQueue m_queue;

	/** Rulesets to be applied */
	RuleRepository m_rules;

};
