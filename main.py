import uvicorn
from loguru import logger

from app.config import config
from app.services.pilot_policy import get_pilot_policy

if __name__ == "__main__":
    _policy = get_pilot_policy()
    if _policy is not None:
        _policy.require_not_api_server()
    logger.info(
        "start server, docs: http://127.0.0.1:" + str(config.listen_port) + "/docs"
    )
    # FFmpeg 探测已经移到 app/services/task.py 的共享任务流水线里，这样
    # API、CLI 和 WebUI 三条路径都能统一覆盖，这里不再单独检查。
    uvicorn.run(
        app="app.asgi:app",
        host=config.listen_host,
        port=config.listen_port,
        reload=config.reload_debug,
        log_level="warning",
    )
