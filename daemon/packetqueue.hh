#pragma once
#include "packet.hh"
#include <mutex>
#include <condition_variable>
#include <queue>

namespace PersonalFirewall{

/** Simple Queue that blocks on read and is thread-safe
 *
 * Does not give strong exception guarentee, but easy to use
 */
template<class T>
class Queue{
public:
	T read();
	void write(T&&);
private:
	std::mutex m_mutex;
	std::condition_variable m_cond;
	std::queue<T> m_queue;
};

typedef Queue<Packet> PacketQueue;

} // end namespace
