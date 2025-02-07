# RS_login_demo
问题1.注意安全的可能性\n
问题1回复：\n
    1.不能明文传输用户的密码，防止在传输过程被抓包泄露（前后端约定密码加解密密钥及算法，前端请求登录接口时对用户输入密码进行加密处理）\n
    2.数据库不能存储密码明文，防止数据库撞库泄露后担负的法律风险（数据库存储不可逆加密的密码，后端在对比密码正不正确时，其实对比的是加密后的哈希值是不是不一样）\n
    3.用户登陆后获取到令牌，令牌需设置有效时间。(令牌解析后校验有效时间，防止令牌泄露后反复使用)\n

问题2.注意权限验证的便捷性，使得其他地方也能使用\n
问题2回复：\n
    复用app/auth.py中token_required装饰器，对其他接口进行token校验\n

问题3.考虑性能、可扩展性，说明如何达到的\n
问题3回复：\n
    性能：\n
        1.数据库优化，优化sql及查询索引\n
        2.使用redis缓存令牌，减少数据库查询次数\n
        3.单节点启动多个进程和线程，充分利用CPU多核资源，例如使用Gunicorn\n
        4.部署多节点服务，使用nginx进行负载均衡\n
        5.使用Celery处理异步任务\n
    可扩展性：\n
        1.数据库分库分表,减轻单节点的数据存储以及数据查询压力\n
        2.服务容器化，部署在k8s上，使用k8s管理多个容器实例，自动根据负载进行扩展和缩减\n


问题4.注意选择的技术栈，说明为什么这样选择\n
问题4回复：\n
    1.选择了flask编写此案例：flask轻量化，并且较为熟悉，哈哈哈\n
    PS: 在python的web框架中，Django和flask比较主流，生态较好，性能差距不大。FastAPI性能比较好，但是生态稍差。框架选择由于受到团队技术历史以及迁移成本的影响，乐于听从团队的安排，我能迅速上手适应新框架。如果是新项目的话，建议使用FastAPI。\n
    2.使用了sqlite存储数据\n
    为了代码本地调试及复现\n
    3.其他\n
    如果应用需要支撑高并发访问（如 1w+ QPS），建议FastAPI+Redis+MYSQL+Celery+Kubernetes方案
