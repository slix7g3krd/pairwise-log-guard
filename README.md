# pairwise-log-guard

审计日志开始记录原始用户输入后，日志注入就能伪造整条记录：换行符把一条日志拆成两条；CRLF 能插入假的 `level=INFO`；ANSI 控制字符能覆盖终端输出；Unicode 行分隔符绕过只查 `\n` 的过滤；JSON 结构化日志里引号和反斜杠没有转义；超长输入把日志截断，后半段伪造；用户可控的 `user=` 字段能覆盖真实身份；日志采集器把多行当栈追踪合并；敏感字段没有脱敏；错误对象直接序列化，带出内部路径。security/log_guard.py 是核心，tests/test_log_guard.py 15个红。要修的是：换行与 CRLF 转义；ANSI 清理；Unicode 分隔符归一；JSON 转义；长度上限；字段顺序固定；身份字段服务端覆盖；多行标记；敏感字段脱敏；异常白名单序列化。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
