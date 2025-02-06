class Deferred {
  constructor() {
    this.promise = new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });

    // Add notify functionality similar to $q.defer()
    this.notifications = [];
    this.notifyListeners = [];

    this.notify = (progress) => {
      this.notifications.push(progress);
      this.notifyListeners.forEach((listener) => listener(progress));
    };

    // Add then/catch/finally methods to match $q.defer() API
    this.then = (onFulfilled, onRejected, onProgress) => {
      if (onProgress) {
        this.notifyListeners.push(onProgress);
        // Send any existing notifications to new listener
        this.notifications.forEach((progress) => onProgress(progress));
      }
      return this.promise.then(onFulfilled, onRejected);
    };

    this.catch = (onRejected) => {
      return this.promise.catch(onRejected);
    };

    this.finally = (onFinally) => {
      return this.promise.finally(onFinally);
    };
  }
}

export default Deferred;
