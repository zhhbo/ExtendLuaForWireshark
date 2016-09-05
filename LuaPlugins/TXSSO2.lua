--[=======[
-------- -------- -------- --------
       Tencent SSO 2 插件
-------- -------- -------- --------
  注意：插件不再重载UDP:8000的Dissector。因为重载可能其它协议的干扰。

        解决方法：任选一条UDP包，右键
        Protocol Preferences(协议首选项) >>>> Try heuristic sub-dissectors first

        解决方法2：Edit(编辑) >>>> Preferences(首选项) >>>> Protocols >>>>
                   UDP >>>> Try heuristic sub-dissectors first 打勾

  插件x86/x64 wireshark 1.11 ~ 2.0.x通用。但强烈建议使用x64 wireshark 2.0.x以获得最佳体验
]=======]
--以下是一些需要预加载的模块
require "TXSSO2/Fields";
require "TXSSO2/Proto";
require "TXSSO2/Packets";
require "TXSSO2/TLV";
require "TXSSO2/Expand";