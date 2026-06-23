#!/usr/bin/env python3
"""
Performance-Optimized VoIP Scanner
Parallelized testing with concurrent execution for maximum speed
"""

import asyncio
import threading
import logging
from typing import Dict, List, Coroutine, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import time

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Performance metrics for scanning"""
    start_time: float
    end_time: float = 0.0
    total_tests: int = 0
    tests_completed: int = 0
    tests_per_second: float = 0.0
    peak_threads: int = 0
    memory_used: float = 0.0
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time > 0 else 0.0
    
    @property
    def completion_percentage(self) -> float:
        return (self.tests_completed / self.total_tests * 100) if self.total_tests > 0 else 0.0

class ParallelExecutor:
    """Executes tests in parallel for maximum speed"""
    
    def __init__(self, max_workers: int = 20, timeout: int = 30):
        self.max_workers = max_workers
        self.timeout = timeout
        self.metrics = PerformanceMetrics(start_time=time.time())
        self.results = []
        self.errors = []
    
    def execute_parallel(self, tasks: List[tuple]) -> List[Dict]:
        """
        Execute multiple tasks in parallel
        tasks: List of (task_name, callable, args) tuples
        """
        logger.info(f"Starting parallel execution with {self.max_workers} workers")
        logger.info(f"Total tasks: {len(tasks)}")
        
        self.metrics.total_tests = len(tasks)
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {}
            
            # Submit all tasks
            for task_name, func, args in tasks:
                try:
                    future = executor.submit(self._execute_with_timeout, task_name, func, args)
                    future_to_task[future] = task_name
                except Exception as e:
                    logger.error(f"Error submitting task {task_name}: {e}")
                    self.errors.append({'task': task_name, 'error': str(e)})
            
            # Collect results as they complete
            for future in as_completed(future_to_task):
                task_name = future_to_task[future]
                try:
                    result = future.result(timeout=self.timeout)
                    results.append(result)
                    self.metrics.tests_completed += 1
                    
                    if self.metrics.tests_completed % 10 == 0:
                        logger.debug(f"Progress: {self.metrics.completion_percentage:.1f}% "
                                   f"({self.metrics.tests_completed}/{self.metrics.total_tests})")
                except Exception as e:
                    logger.error(f"Task {task_name} failed: {e}")
                    self.errors.append({'task': task_name, 'error': str(e)})
                    self.metrics.tests_completed += 1
        
        self.metrics.end_time = time.time()
        self.metrics.tests_per_second = (self.metrics.tests_completed / self.metrics.duration 
                                        if self.metrics.duration > 0 else 0)
        
        logger.info(f"Parallel execution complete: {self.metrics.tests_per_second:.1f} tests/sec")
        return results
    
    def _execute_with_timeout(self, task_name: str, func, args) -> Dict:
        """Execute function with timeout"""
        try:
            start = time.time()
            result = func(*args) if args else func()
            duration = time.time() - start
            
            return {
                'task': task_name,
                'success': True,
                'result': result,
                'duration': duration
            }
        except Exception as e:
            logger.error(f"Task {task_name} error: {e}")
            return {
                'task': task_name,
                'success': False,
                'error': str(e),
                'duration': time.time() - start
            }
    
    def execute_async(self, coroutines: List[Coroutine]) -> List[Any]:
        """Execute async coroutines"""
        logger.info(f"Starting async execution with {len(coroutines)} tasks")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(asyncio.gather(*coroutines, return_exceptions=True))
            return results
        finally:
            loop.close()
    
    def get_metrics(self) -> PerformanceMetrics:
        """Get performance metrics"""
        return self.metrics
