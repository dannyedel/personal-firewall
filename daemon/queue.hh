#pragma once
#include <mutex>
#include <condition_variable>
#include <queue>
#include <stdexcept>

#include <boost/log/trivial.hpp>

namespace PersonalFirewall{

/** The queue is being shut down
 *
 * This is a possible response to read()
 */
struct ShutdownException: public std::runtime_error {
ShutdownException(): runtime_error("System Shutdown") {}
};

/** Simple Queue that blocks on read and is thread-safe
 *
 * Does not give strong exception guarentee, but easy to use
 */
template<class T>
class Queue{
public:
	T read();
	void write(T&&);

	// This class is not allowed to be copied
	Queue& operator = (const Queue&) =delete;

	// Destructor, calls shutdown();
	~Queue();

	// This interrupts all reading threads
	void shutdown();

	bool is_shutdown() const;
private:
	mutable std::mutex m_mutex;
	std::condition_variable m_cond;
	std::queue<T> m_queue;
	bool m_shutdown = false;
};


// implementation
template<class T>
T Queue<T>::read() {
	using namespace std;
	// Lock the mutex
	unique_lock<mutex> lock{m_mutex};
	while( !m_shutdown && m_queue.empty() ) {
		m_cond.wait(lock);
	}
	if ( m_shutdown ) {
		BOOST_LOG_TRIVIAL(debug) << "Shutdown request detected";
		throw ShutdownException();
	}
	// Move the first element outside
	T ret{ move( m_queue.front() ) };
	// Pop the queue head
	m_queue.pop();
	// return the temporary
	return ret;
}

template<class T>
void Queue<T>::write(T&& newElement) {
	using namespace std;

	// Lock the mutex, and append new element
	unique_lock<mutex> lock(m_mutex);
	m_queue.emplace(newElement);

	// Notify the waiting threads
	m_cond.notify_all();
}

template<class T>
void Queue<T>::shutdown() {
	using namespace std;
	unique_lock<mutex> lock(m_mutex);
	m_shutdown = true;
	m_cond.notify_all();
}

template<class T>
Queue<T>::~Queue() {
	shutdown();
}

template<class T>
bool Queue<T>::is_shutdown() const {
	using namespace std;
	unique_lock<mutex> lock{m_mutex};
	return m_shutdown;
}

} // end namespace
