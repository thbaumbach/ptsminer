//===
// by xolokram/TB
// 2013
//===

#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <map>

#include "main_poolminer.hpp"

#define VERSION_MAJOR 0
#define VERSION_MINOR 5
#define VERSION_EXT "RC0"

#define MAX_THREADS 64

/*********************************
* global variables, structs and extern functions
*********************************/

size_t thread_num_max;
static size_t fee_to_pay;
static size_t miner_id;
static boost::asio::ip::tcp::socket* socket_to_server;
static boost::posix_time::ptime t_start;
static std::map<int,unsigned long> statistics;
static bool running;
static volatile int submitting_share;
std::string pool_username;
std::string pool_password;

/*********************************
* class CBlockProviderGW to (incl. SUBMIT_BLOCK)
*********************************/

class CBlockProviderGW : public CBlockProvider {
public:

	CBlockProviderGW() : CBlockProvider(), nTime_offset(0), _block(NULL) {}

	virtual ~CBlockProviderGW() { /* TODO */ }

	virtual unsigned int GetAdjustedTimeWithOffset(unsigned int thread_id) {
		return nTime_offset + ((((unsigned int)time(NULL) + thread_num_max) / thread_num_max) * thread_num_max) + thread_id;
	}

	virtual blockHeader_t* getBlock(unsigned int thread_id, unsigned int last_time) {
		boost::unique_lock<boost::shared_mutex> lock(_mutex_getwork);
		if (_block == NULL) return NULL;
		blockHeader_t* block = new blockHeader_t;
		memcpy(block, _block, 80+32+8);
		unsigned int new_time = GetAdjustedTimeWithOffset(thread_id);
		if (new_time == last_time)
			new_time += thread_num_max;
		block->nTime = new_time;
		//std::cout << "[WORKER" << thread_id << "] got_work block=" << block->GetHash().ToString().c_str() << std::endl;
		return block;
	}
	
	virtual blockHeader_t* getOriginalBlock() {
		return _block;
	}

	void setBlocksFromData(unsigned char* data) {
		blockHeader_t* block = new blockHeader_t;
		memcpy(block, data, 80); //0-79
		block->birthdayA = 0;    //80-83
		block->birthdayB = 0;    //84-87
		memcpy(((unsigned char*)block)+88,data+80, 32);
		//
		unsigned int nTime_local = time(NULL);
		unsigned int nTime_server = block->nTime;
		nTime_offset = nTime_local > nTime_server ? 0 : (nTime_server-nTime_local);
		//
		blockHeader_t* old_block = NULL;
		{
			boost::unique_lock<boost::shared_mutex> lock(_mutex_getwork);
			old_block = _block;
			_block = block;
		}
		if (old_block != NULL) delete old_block;
	}

	void submitBlock(blockHeader_t *block) {
		blockHeader_t submitblock; //!
		memcpy((unsigned char*)&submitblock, (unsigned char*)block, 88);
		std::cout << "[WORKER] collision found: " << submitblock.birthdayA << " <-> " << submitblock.birthdayB << " @ " << totalCollisionCount << std::endl;
		boost::system::error_code submit_error = boost::asio::error::host_not_found;
		boost::asio::write(*socket_to_server, boost::asio::buffer((unsigned char*)&submitblock, 88), boost::asio::transfer_all(), submit_error); //FaF
		//if (submit_error)
		//	std::cout << submit_error << " @ submit" << std::endl;
	}

	void forceReconnect() {
		std::cout << "force reconnect if possible!" << std::endl;
		//TODO: THREAD SAFETY
		if (socket_to_server != NULL) {
			boost::system::error_code close_error;
			socket_to_server->close(close_error);
			//if (close_error)
			//	std::cout << close_error << " @ close" << std::endl;
		}
	}

protected:
	unsigned int nTime_offset;
	boost::shared_mutex _mutex_getwork;
	blockHeader_t* _block;
};

/*********************************
* multi-threading
*********************************/

class CMasterThreadStub {
public:
  virtual void wait_for_master() = 0;
  virtual boost::shared_mutex& get_working_lock() = 0;
};

class CWorkerThread { // worker=miner
public:

	CWorkerThread(CMasterThreadStub *master, unsigned int id, CBlockProviderGW *bprovider)
		: _collisionMap(NULL), _working_lock(NULL), _id(id), _master(master), _bprovider(bprovider), _thread(&CWorkerThread::run, this) {
		_collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
		}

	void run() {
		std::cout << "[WORKER" << _id << "] Hello, World!" << std::endl;
		_master->wait_for_master();
		std::cout << "[WORKER" << _id << "] GoGoGo!" << std::endl;
		boost::this_thread::sleep(boost::posix_time::seconds(1));
		blockHeader_t* thrblock = NULL;
		while (running) {
			thrblock = _bprovider->getBlock(_id, thrblock == NULL ? 0 : thrblock->nTime);
			if (thrblock != NULL)
				protoshares_process_512(thrblock, _collisionMap, _bprovider);
			else
				boost::this_thread::sleep(boost::posix_time::seconds(1));
		}
		std::cout << "[WORKER" << _id << "] Bye Bye!" << std::endl;
	}

	void work() { // called from within master thread
		_working_lock = new boost::shared_lock<boost::shared_mutex>(_master->get_working_lock());
	}

protected:
  uint32* _collisionMap;
  boost::shared_lock<boost::shared_mutex> *_working_lock;
  unsigned int _id;
  CMasterThreadStub *_master;
  CBlockProviderGW  *_bprovider;
  boost::thread _thread;
};

class CMasterThread : public CMasterThreadStub {
public:

  CMasterThread(CBlockProviderGW *bprovider) : CMasterThreadStub(), _bprovider(bprovider) {}

  void run() {

	{
		boost::unique_lock<boost::shared_mutex> lock(_mutex_master);
		std::cout << "spawning " << thread_num_max << " worker thread(s)" << std::endl;

		for (unsigned int i = 0; i < thread_num_max; ++i) {
			CWorkerThread *worker = new CWorkerThread(this, i, _bprovider);
			worker->work();
		}
	}

    boost::asio::io_service io_service;
    boost::asio::ip::tcp::resolver resolver(io_service); //resolve dns
	boost::asio::ip::tcp::resolver::query query("ptsmine.beeeeer.org", "1337");
	//boost::asio::ip::tcp::resolver::query query("127.0.0.1", "1337");
    boost::asio::ip::tcp::resolver::iterator endpoint;
	boost::asio::ip::tcp::resolver::iterator end;
	boost::asio::ip::tcp::no_delay nd_option(true);
	boost::asio::socket_base::keep_alive ka_option(true);

	while (running) {
		endpoint = resolver.resolve(query);
		boost::scoped_ptr<boost::asio::ip::tcp::socket> socket;
		boost::system::error_code error_socket = boost::asio::error::host_not_found;
		while (error_socket && endpoint != end)
		{
		  //socket->close();
		  socket.reset(new boost::asio::ip::tcp::socket(io_service));
		  boost::asio::ip::tcp::endpoint tcp_ep = *endpoint++;
		  socket->connect(tcp_ep, error_socket);
		  std::cout << "connecting to " << tcp_ep << std::endl;
		}
		socket->set_option(nd_option);
		socket->set_option(ka_option);

		if (error_socket) {
			std::cout << error_socket << std::endl;
			boost::this_thread::sleep(boost::posix_time::seconds(10));
			continue;
		}

		{ //send hello message
			char* hello = new char[pool_username.length()+/*v0.2/0.3=*/2+/*v0.4=*/20+/*v0.7=*/1+pool_password.length()];
			memcpy(hello+1, pool_username.c_str(), pool_username.length());
			*((unsigned char*)hello) = pool_username.length();
			*((unsigned char*)(hello+pool_username.length()+1)) = 0; //hi, i'm v0.4+
			*((unsigned char*)(hello+pool_username.length()+2)) = VERSION_MAJOR;
			*((unsigned char*)(hello+pool_username.length()+3)) = VERSION_MINOR;
			*((unsigned char*)(hello+pool_username.length()+4)) = thread_num_max;
			*((unsigned char*)(hello+pool_username.length()+5)) = fee_to_pay;
			*((unsigned short*)(hello+pool_username.length()+6)) = miner_id;
			*((unsigned int*)(hello+pool_username.length()+8)) = 0;
			*((unsigned int*)(hello+pool_username.length()+12)) = 0;
			*((unsigned int*)(hello+pool_username.length()+16)) = 0;
			*((unsigned char*)(hello+pool_username.length()+20)) = pool_password.length();
			memcpy(hello+pool_username.length()+21, pool_password.c_str(), pool_password.length());
			*((unsigned short*)(hello+pool_username.length()+21+pool_password.length())) = 0; //EXTENSIONS
			boost::system::error_code error;
			socket->write_some(boost::asio::buffer(hello, pool_username.length()+2+20+1+pool_password.length()), error);
			//if (error)
			//	std::cout << error << " @ write_some_hello" << std::endl;
			delete[] hello;
		}

		socket_to_server = socket.get(); //TODO: lock/mutex

		int reject_counter = 0;
		bool done = false;
		while (!done) {
			int type = -1;
			{ //get the data header
				unsigned char buf = 0; //get header
				boost::system::error_code error;
				size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(&buf, 1), boost::asio::transfer_all(), error);
				if (error == boost::asio::error::eof)
					break; // Connection closed cleanly by peer.
				else if (error) {
					//std::cout << error << " @ read_some1" << std::endl;
					break;
				}
				type = buf;
				if (len != 1)
					std::cout << "error on read1: " << len << " should be " << 1 << std::endl;
			}

			switch (type) {
				case 0: {
					size_t buf_size = 112; //*thread_num_max;
					unsigned char* buf = new unsigned char[buf_size]; //get header
					boost::system::error_code error;
					size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(buf, buf_size), boost::asio::transfer_all(), error);
					if (error == boost::asio::error::eof) {
						done = true;
						break; // Connection closed cleanly by peer.
					} else if (error) {
						//std::cout << error << " @ read2a" << std::endl;
						done = true;
						break;
					}
					if (len == buf_size) {
						_bprovider->setBlocksFromData(buf);
						std::cout << "[MASTER] work received"<< std::endl;
					} else
						std::cout << "error on read2a: " << len << " should be " << buf_size << std::endl;
					delete[] buf;
				} break;
				case 1: {
					size_t buf_size = 4;
					int buf; //get header
					boost::system::error_code error;
					size_t len = boost::asio::read(*socket_to_server, boost::asio::buffer(&buf, buf_size), boost::asio::transfer_all(), error);
					if (error == boost::asio::error::eof) {
						done = true;
						break; // Connection closed cleanly by peer.
					} else if (error) {
						//std::cout << error << " @ read2b" << std::endl;
						done = true;
						break;
					}
					if (len == buf_size) {
						int retval = buf > 1000 ? 1 : buf;
						std::cout << "[MASTER] submitted share -> " <<
							(retval == 0 ? "REJECTED" : retval < 0 ? "STALE" : retval ==
							1 ? "BLOCK" : "SHARE") << std::endl;
						std::map<int,unsigned long>::iterator it = statistics.find(retval);
						if (retval > 0)
							reject_counter = 0;
						else
							reject_counter++;
//  					if (reject_counter >= 3) {
//  						std::cout << "too many rejects (3) in a row, forcing reconnect." << std::endl;
//  						socket->close();
//  						done = true;
//  					}
						if (it == statistics.end())
							statistics.insert(std::pair<int,unsigned long>(retval,1));
						else
							statistics[retval]++;
						stats_running();
					} else
						std::cout << "error on read2b: " << len << " should be " << buf_size << std::endl;
				} break;
				case 2: {
					//PING-PONG EVENT, nothing to do
				} break;
				default: {
					//std::cout << "unknown header type = " << type << std::endl;
				}
			}
		}

		socket_to_server = NULL; //TODO: lock/mutex
		boost::this_thread::sleep(boost::posix_time::seconds(10));
	}
  }

  ~CMasterThread() {}

  void wait_for_master() {
    boost::shared_lock<boost::shared_mutex> lock(_mutex_master);
  }

  boost::shared_mutex& get_working_lock() {
    return _mutex_working;
  }

private:

  void wait_for_workers() {
    boost::unique_lock<boost::shared_mutex> lock(_mutex_working);
  }

  CBlockProviderGW  *_bprovider;

  boost::shared_mutex _mutex_master;
  boost::shared_mutex _mutex_working;

	// Provides real time stats
	void stats_running() {
		if (!running) return;
		std::cout << std::fixed;
		std::cout << std::setprecision(1);
		boost::posix_time::ptime t_end = boost::posix_time::second_clock::local_time();
		unsigned long rejects = 0;
		unsigned long stale = 0;
		unsigned long valid = 0;
		unsigned long blocks = 0;
		for (std::map<int,unsigned long>::iterator it = statistics.begin(); it != statistics.end(); ++it) {
			if (it->first < 0) stale += it->second;
			if (it->first == 0) rejects = it->second;
			if (it->first == 1) blocks = it->second;
			if (it->first > 1) valid += it->second;
		}
		std::cout << "[STATS] " << t_end << " | ";
		if ((t_end - t_start).total_seconds() > 0)
			std::cout << static_cast<double>(totalCollisionCount) / (static_cast<double>((t_end - t_start).total_seconds()) / 60.0) << " c/m | ";
		if (valid+blocks+rejects+stale > 0) {
			std::cout << "VL: " << valid+blocks << " (" << (static_cast<double>(valid+blocks) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
			std::cout << "RJ: " << rejects << " (" << (static_cast<double>(rejects) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%), ";
			std::cout << "ST: " << stale << " (" << (static_cast<double>(stale) / static_cast<double>(valid+blocks+rejects+stale)) * 100.0 << "%)" << std::endl;
		} else {
			std::cout <<  "VL: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "RJ: " << 0 << " (" << 0.0 << "%), ";
			std::cout <<  "ST: " << 0 << " (" << 0.0 << "%)" << std::endl;
		}
	}
};

/*********************************
* exit / end / shutdown
*********************************/

void exit_handler() {
	//cleanup for not-retarded OS
	if (socket_to_server != NULL) {
		socket_to_server->close();
		socket_to_server = NULL;
	}
	running = false;
}

#if defined(__MINGW32__) || defined(__MINGW64__)

//#define WIN32_LEAN_AND_MEAN
//#include <windows.h>

BOOL WINAPI ctrl_handler(DWORD dwCtrlType) {
	//'special' cleanup for windows
	switch(dwCtrlType) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT: {
			if (socket_to_server != NULL) {
				socket_to_server->close();
				socket_to_server = NULL;
			}
			running = false;
		} break;
		default: break;
	}
	return FALSE;
}

#elif defined(__GNUG__) && !defined(__APPLE__)

static sighandler_t set_signal_handler (int signum, sighandler_t signalhandler) {
   struct sigaction new_sig, old_sig;
   new_sig.sa_handler = signalhandler;
   sigemptyset (&new_sig.sa_mask);
   new_sig.sa_flags = SA_RESTART;
   if (sigaction (signum, &new_sig, &old_sig) < 0)
      return SIG_ERR;
   return old_sig.sa_handler;
}

void ctrl_handler(int signum) {
	exit(1);
}

#endif

/*********************************
* main - this is where it begins
*********************************/
int main(int argc, char **argv)
{
  std::cout << "********************************************" << std::endl;
  std::cout << "*** ptsminer - Pts Pool Miner v" << VERSION_MAJOR << "." << VERSION_MINOR << " " << VERSION_EXT << std::endl;
  std::cout << "*** by xolokram/TB - www.beeeeer.org - glhf" << std::endl;
  std::cout << "*** thanks to jh00, testix & Co." << std::endl;
  std::cout << "***" << std::endl;
  std::cout << "*** press CTRL+C to exit" << std::endl;
  std::cout << "********************************************" << std::endl;

  t_start = boost::posix_time::second_clock::local_time();
  running = true;

#if defined(__MINGW32__) || defined(__MINGW64__)
  SetConsoleCtrlHandler(ctrl_handler, TRUE);
#elif defined(__GNUG__) && !defined(__APPLE__)
  set_signal_handler(SIGINT, ctrl_handler);
#endif

  if (argc != 3)
  {
    std::cerr << "usage: " << argv[0] << " <user> <threads-to-use>" << std::endl;
    return EXIT_FAILURE;
  }

  const int atexit_res = std::atexit(exit_handler);
  if (atexit_res != 0)
    std::cerr << "atexit registration failed, shutdown will be dirty!" << std::endl;

  // init everything:
  socket_to_server = NULL;
  thread_num_max = atoi(argv[2]); //GetArg("-genproclimit", 1); // what about boost's hardware_concurrency() ?
  fee_to_pay = 0; //GetArg("-poolfee", 3);
  miner_id = 0; //GetArg("-minerid", 0);
  pool_username = argv[1]; //GetArg("-pooluser", "");
  pool_password = "blabla"; //GetArg("-poolpassword", "");

  if (thread_num_max == 0 || thread_num_max > MAX_THREADS)
  {
    std::cerr << "usage: " << "current maximum supported number of threads = " << MAX_THREADS << std::endl;
    return EXIT_FAILURE;
  }

  {
	uint32 pw[8];
	sha256_ctx c256;
	sha256_init(&c256);
	sha256_update(&c256, (unsigned char*)pool_password.c_str(), pool_password.size());
	sha256_final(&c256, (uint8*)pw);
    std::stringstream ss;
    ss << std::setw(5) << std::setfill('0') << std::hex << (pw[0] ^ pw[5] ^ pw[2] ^ pw[7]) << (pw[4] ^ pw[1] ^ pw[6] ^ pw[3]);
    pool_password = ss.str();
  }

  // ok, start mining:
  CBlockProviderGW* bprovider = new CBlockProviderGW();
  CMasterThread *mt = new CMasterThread(bprovider);
  mt->run();

  // end:
  return EXIT_SUCCESS;
}

/*********************************
* and this is where it ends
*********************************/
