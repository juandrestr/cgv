import time, os, redis

_r = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))

def throttle(user_uuid: str, bucket: str, limit: int, window_sec: int):
    key = f"rl:{bucket}:{user_uuid}"
    now = int(time.time())
    p = _r.pipeline()
    p.zremrangebyscore(key, 0, now - window_sec)   # drop old events
    p.zadd(key, {str(now): now})                   # add current
    p.zcard(key)                                   # count in window
    p.expire(key, window_sec)                      # TTL
    _, _, count, _ = p.execute()
    if count > limit:
        raise RuntimeError("rate_limit_exceeded")
