//facebook的工业级实现：https://github.com/facebook/folly/blob/master/folly/experimental/FunctionScheduler.h
//本文对原代码做些许删减、调整，保留主体，便于阅读

//.h
#pragma once
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>
#include <string>

/**
 * Schedules any number of functions to run at various intervals. E.g.,
 *
 *   FunctionScheduler fs;
 *
 *   fs.addFunction([&] { LOG(INFO) << "tick..."; }, seconds(1), "ticker");
 *   fs.addFunction(std::bind(&TestClass::doStuff, this), minutes(5), "stuff");
 *   fs.start();
 *   ........
 *   fs.cancelFunction("ticker");
 *   fs.addFunction([&] { LOG(INFO) << "tock..."; }, minutes(3), "tocker");
 *   ........
 *   fs.shutdown();
 *
 *
 * Note: the class uses only one thread - if you want to use more than one
 *       thread, either use multiple FunctionScheduler objects, or check out
 *       ThreadedRepeatingFunctionRunner.h for a much simpler contract of
 *       "run each function periodically in its own thread".
 *
 * start() schedules the functions, while shutdown() terminates further
 * scheduling.
 */

 //A type alias for function that is called to determine the time interval for the next scheduled run.
using IntervalDistributionFunc = std::function<std::chrono::microseconds()>;

//A type alias for function that returns the next run time, given the current start time.
using NextRunTimeFunc = std::function<std::chrono::steady_clock::time_point(std::chrono::steady_clock::time_point)>;

struct RepeatFunc
{
	std::function<void()> cb;
	NextRunTimeFunc nextRunTimeFunc;
	std::chrono::steady_clock::time_point nextRunTime;
	std::string name;
	std::chrono::microseconds startDelay;
	std::string intervalDescr;
	bool runOnce;

	RepeatFunc(std::function<void()>&& cback, IntervalDistributionFunc&& intervalFn, const std::string& nameID,
		const std::string& intervalDistDescription, std::chrono::microseconds delay, bool once) :
		cb(std::move(cback)),
		nextRunTimeFunc(getNextRunTimeFunc(std::move(intervalFn))),
		name(nameID),
		intervalDescr(intervalDistDescription),
		startDelay(delay),
		runOnce(once) {}

	static NextRunTimeFunc getNextRunTimeFunc(IntervalDistributionFunc&& intervalFn)
	{
		return[intervalFn = std::move(intervalFn)](std::chrono::steady_clock::time_point curTime) mutable
		{
			return curTime + intervalFn();
		};
	}

	std::chrono::steady_clock::time_point getNextRunTime() const
	{
		return nextRunTime;
	}
	void setNextRunTimeSteady()
	{
		nextRunTime = nextRunTimeFunc(nextRunTime);
	}
	void setNextRunTimeStrict(std::chrono::steady_clock::time_point curTime)
	{
		nextRunTime = nextRunTimeFunc(curTime);
	}
	void resetNextRunTime(std::chrono::steady_clock::time_point curTime)
	{
		nextRunTime = curTime + startDelay;
	}
	void cancel()
	{
		// Simply reset cb to an empty function.
		cb = {};
	}
	bool isValid() const
	{
		return bool(cb);
	}
};

class FunctionScheduler 
{
public:
	FunctionScheduler();
	~FunctionScheduler();

	/**
	 * Starts the scheduler.
	 * Returns false if the scheduler was already running.
	 */
	bool start();

	/**
	 * Stops the FunctionScheduler.
	 * It may be restarted later by calling start() again.
	 *	Returns false if the scheduler was not running.
	 */
	bool shutdown();

	/**
	 * By default steady is false, meaning schedules may lag behind overtime.
	 * This could be due to long running tasks or time drift because of randomness
	 * in thread wakeup time.
	 * By setting steady to true, FunctionScheduler will attempt to catch up.
	 * i.e. more like a cronjob
	 *
	 * NOTE: it's only safe to set this before calling start()
	 */
	void setSteady(bool steady) { steady_ = steady; }

	/**
	 * Adds a new function to the FunctionScheduler.
	 * Functions will not be run until start() is called.  When start() is called, each function will be run after its specified startDelay.
	 * Functions may also be added after start() has been called, in which case startDelay is still honored.
	 * Throws an exception on error.  In particular, each function must have a unique name--two functions cannot be added with the same name.
	 */
	void addFunction(std::function<void()>&& cb, std::chrono::microseconds interval, std::string nameID, std::chrono::microseconds startDelay = std::chrono::microseconds(0));

	//Adds a new function to the FunctionScheduler to run only once.
	void addFunctionOnce(std::function<void()>&& cb, std::string nameID, std::chrono::microseconds startDelay = std::chrono::microseconds(0));

	/**
	 * Cancels the function with the specified name, so it will no longer be run.
	 * Returns false if no function exists with the specified name.
	 */
	bool cancelFunction(std::string nameID);
	bool cancelFunctionAndWait(std::string nameID);
private:

	struct RunTimeOrder 
	{
		bool operator()(const std::unique_ptr<RepeatFunc>& f1,const std::unique_ptr<RepeatFunc>& f2) const 
		{
			return f1->getNextRunTime() > f2->getNextRunTime();
		}
	};

	typedef std::vector<std::unique_ptr<RepeatFunc>> FunctionHeap;
	typedef std::unordered_map<std::string, RepeatFunc*> FunctionMap;

	void run();
	void runOneFunction(std::unique_lock<std::mutex>& lock,std::chrono::steady_clock::time_point now);

	template <typename IntervalFunc>
	void addFunctionToHeapChecked(std::function<void()>&& cb,IntervalFunc&& fn,const std::string& nameID,
		const std::string& intervalDescr, std::chrono::microseconds startDelay, bool runOnce);

	std::thread thread_;
	std::mutex mutex_;
	bool running_{ false };

	FunctionHeap functions_;// This is a heap, ordered by next run time.
	FunctionMap functionsMap_;
	RunTimeOrder fnCmp_;

	// The function currently being invoked by the running thread.This is null when the running thread is idle
	RepeatFunc* currentFunction_{ nullptr };

	// Condition variable that is signalled whenever a new function is added or when the FunctionScheduler is stopped.
	std::condition_variable runningCondvar_;

	bool steady_{ false };
	bool cancellingCurrentFunction_{ false };
};

//.cpp
#include <random>
#include <iostream>
#include <algorithm>
#include <cassert>
#include <stdexcept>
#include "timer.h"

using std::chrono::microseconds;
using std::chrono::steady_clock;

struct ConstIntervalFunctor 
{
	const microseconds constInterval;
	explicit ConstIntervalFunctor(microseconds interval): constInterval(interval)
	{
		if (interval < microseconds::zero())
		{
			throw std::invalid_argument("FunctionScheduler: time interval must be non-negative");
		}
	}
	microseconds operator()() const { return constInterval; }
};

FunctionScheduler::FunctionScheduler() = default;

FunctionScheduler::~FunctionScheduler() 
{
	shutdown();
}

bool FunctionScheduler::start()
{
	std::unique_lock<std::mutex> lock(mutex_);
	if (running_)
	{
		return false;
	}

	std::cout << "Starting FunctionScheduler with " << functions_.size() << " functions.";
	auto now = steady_clock::now();
	// Reset the next run time. for all functions. this is needed since one can shutdown() and start() again
	for (const auto& f : functions_)
	{
		f->resetNextRunTime(now);
		std::cout << "   - func: " << (f->name.empty() ? "(anon)" : f->name.c_str())
			<< ", period = " << f->intervalDescr
			<< ", delay = " << f->startDelay.count() << "ms" << std::endl;
	}
	std::make_heap(functions_.begin(), functions_.end(), fnCmp_);

	thread_ = std::thread([&] { this->run(); });
	running_ = true;

	return true;
}

bool FunctionScheduler::shutdown()
{
	{
		std::lock_guard<std::mutex> lock(mutex_);
		if (!running_)
		{
			return false;
		}

		running_ = false;
		runningCondvar_.notify_one();
	}
	thread_.join();
	return true;
}

void FunctionScheduler::addFunction(std::function<void()>&& cb, microseconds interval, std::string nameID, microseconds startDelay)
{
	addFunctionToHeapChecked(std::move(cb), ConstIntervalFunctor(interval), nameID, std::to_string(interval.count()) + "us", startDelay, false /*runOnce*/);
}

void FunctionScheduler::addFunctionOnce(std::function<void()>&& cb, std::string nameID, microseconds startDelay) 
{
	addFunctionToHeapChecked(std::move(cb), ConstIntervalFunctor(microseconds::zero()), nameID, "once", startDelay, true /*runOnce*/);
}

template <typename IntervalFunc>
void FunctionScheduler::addFunctionToHeapChecked(std::function<void()>&& cb, IntervalFunc&& fn, const std::string& nameID, const std::string& intervalDescr, microseconds startDelay, bool runOnce)
{
	if (!cb) 
	{
		throw std::invalid_argument("FunctionScheduler: Scheduled function must be set");
	}
	if (startDelay < microseconds::zero()) 
	{
		throw std::invalid_argument("FunctionScheduler: start delay must be non-negative");
	}

	std::unique_lock<std::mutex> lock(mutex_);
	auto it = functionsMap_.find(nameID);
	if (it != functionsMap_.end() && it->second->isValid()) 
	{
		throw std::invalid_argument("FunctionScheduler: a function named \"" + nameID +"\" already exists");
	}
	if (currentFunction_ && currentFunction_->name == nameID) 
	{
		throw std::invalid_argument("FunctionScheduler: a function named \"" + nameID + "\" already exists");
	}

	std::unique_ptr<RepeatFunc> func = std::make_unique<RepeatFunc>(std::move(cb), std::forward<IntervalFunc>(fn), nameID, intervalDescr, startDelay, runOnce);

	assert(lock.mutex() == &mutex_);
	assert(lock.owns_lock());

	functions_.push_back(std::move(func));
	functionsMap_[functions_.back()->name] = functions_.back().get();
	if (running_) 
	{
		functions_.back()->resetNextRunTime(steady_clock::now());
		std::push_heap(functions_.begin(), functions_.end(), fnCmp_);
		// Signal the running thread to wake up and see if it needs to change its current scheduling decision.
		runningCondvar_.notify_one();
	}
}

bool FunctionScheduler::cancelFunction(std::string nameID) 
{
	std::unique_lock<std::mutex> lock(mutex_);
	if (currentFunction_ && currentFunction_->name == nameID) 
	{
		functionsMap_.erase(currentFunction_->name);
		// This function is currently being run. Clear currentFunction_
		// The running thread will see this and won't reschedule the function.
		currentFunction_ = nullptr;
		cancellingCurrentFunction_ = true;
		return true;
	}
	auto it = functionsMap_.find(nameID);
	if (it != functionsMap_.end() && it->second->isValid()) 
	{
		functionsMap_.erase(it->second->name);
		it->second->cancel();
		return true;
	}

	return false;
}

bool FunctionScheduler::cancelFunctionAndWait(std::string nameID) 
{
	std::unique_lock<std::mutex> lock(mutex_);
	if (currentFunction_ && currentFunction_->name == nameID) 
	{
		functionsMap_.erase(currentFunction_->name);
		// This function is currently being run. Clear currentFunction_
		// The running thread will see this and won't reschedule the function.
		currentFunction_ = nullptr;
		cancellingCurrentFunction_ = true;
		runningCondvar_.wait(lock, [this]() { return !cancellingCurrentFunction_; });
		return true;
	}

	auto it = functionsMap_.find(nameID);
	if (it != functionsMap_.end() && it->second->isValid()) 
	{
		functionsMap_.erase(it->second->name);
		it->second->cancel();
		return true;
	}

	return false;
}

void FunctionScheduler::run() 
{
	std::unique_lock<std::mutex> lock(mutex_);
	while (running_) 
	{
		if (functions_.empty()) 
		{
			runningCondvar_.wait(lock);
			continue;
		}

		const auto now = steady_clock::now();

		std::pop_heap(functions_.begin(), functions_.end(), fnCmp_);
		if (!functions_.back()->isValid()) 
		{
			functions_.pop_back();
			continue;
		}

		const auto sleepTime = functions_.back()->getNextRunTime() - now;
		if (sleepTime < microseconds::zero()) 
		{
			runOneFunction(lock, now);
			runningCondvar_.notify_all();
		}
		else 
		{
			// Re-add the function to the heap, and wait until we actually need to run it.
			std::push_heap(functions_.begin(), functions_.end(), fnCmp_);
			runningCondvar_.wait_for(lock, sleepTime);
		}
	}
}

void FunctionScheduler::runOneFunction(std::unique_lock<std::mutex>& lock, steady_clock::time_point now) 
{
	assert(lock.mutex() == &mutex_);
	assert(lock.owns_lock());

	// The function to run will be at the end of functions_ already.
	// Fully remove it from functions_ now.
	// We need to release mutex_ while we invoke this function, and we need to maintain the heap property on functions_ while mutex_ is unlocked.
	auto func = std::move(functions_.back());
	functions_.pop_back();
	if (!func->cb) 
	{
		std::cout << func->name << "function has been canceled while waiting" << std::endl;
		return;
	}
	currentFunction_ = func.get();
	if (steady_) 
	{
		// This allows scheduler to catch up
		func->setNextRunTimeSteady();
	}
	else 
	{
		// Note that we set nextRunTime based on the current time where we started
		// the function call, rather than the time when the function finishes.
		// This ensures that we call the function once every time interval, as
		// opposed to waiting time interval seconds between calls.  (These can be
		// different if the function takes a significant amount of time to run.)
		func->setNextRunTimeStrict(now);
	}

	lock.unlock();

	try 
	{
		std::cout << "Now running " << func->name << std::endl;
		func->cb();
	}
	catch (const std::exception& ex) 
	{
		std::cout << "Error running the scheduled function <" << func->name<< ">: " << ex.what() << std::endl;
	}

	lock.lock();

	if (!currentFunction_) 
	{
		// The function was cancelled while we were running it. We shouldn't reschedule it;
		cancellingCurrentFunction_ = false;
		return;
	}
	if (currentFunction_->runOnce) 
	{
		// Don't reschedule if the function only needed to run once.
		functionsMap_.erase(currentFunction_->name);
		currentFunction_ = nullptr;
		return;
	}

	// Re-insert the function into our functions_ heap.
	// We only maintain the heap property while running_ is set.  (running_ may have been cleared while we were invoking the user's function.)
	functions_.push_back(std::move(func));

	// Clear currentFunction_
	currentFunction_ = nullptr;

	if (running_) 
	{
		std::push_heap(functions_.begin(), functions_.end(), fnCmp_);
	}
}