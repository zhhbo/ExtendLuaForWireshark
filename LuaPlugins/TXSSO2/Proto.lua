--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Proto
-------- -------- -------- --------

返回Proto对象
]=======]
--[=======[
●
  filter      txsso2                  --以此filter单独提取TX SSO2部分
]=======]
local proto = Proto( "TXSSO2", "Tencent SSO Protocol ver.2" );

-------- -------- -------- --------
local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );
proto.fields = fields;

-------- -------- -------- --------
proto.prefs.port = Pref.uint( "默认UDP端口", 8000 );  --只做UDP 8000端口解析，其它TCP啥的不管了
proto.prefs.alvl = Pref.enum(
  "解析粒度", alvlD, "控制解析粒度",
  {
    {1, "仅识别",        alvlS },
    {2, "详细细节展示",  alvlD },
  },
  true );
  
--[=======[
●
  在Protocol Preferences(协议首选项)中，你可以选择：
    【选择以向KeyChain加入Key】添加指定的Key
    【选择以向KeyChain加入PsSaltKey】指定QQ号和密码用于TLV_0006解密
    【查看KeyChain】以查看KeyChain中所有的Key与KeyName的对应关系。
]=======]
local keychain = require "TXSSO2/KeyChain";
local use_pref;
local add_key = false;
proto.prefs.add_key = Pref.bool( "选择以向KeyChain加入Key" , add_key );
local add_pskey = false;
proto.prefs.add_pskey = Pref.bool( "选择以向KeyChain加入PsSaltKey" , add_pskey );
local show_keychain = false;
proto.prefs.show_keychain = Pref.bool( "查看KeyChain" , show_keychain );

--由于新版的bool改变不触发proto.prefs_changed，所以这里不采用
function proto.init()
  if not use_pref then
    --这里保证首次加载不触发
    use_pref = true;
    add_key = proto.prefs.add_key;
    add_pskey = proto.prefs.add_pskey;
    show_keychain = proto.prefs.show_keychain;
  end
  
  if add_key ~= proto.prefs.add_key then
    new_dialog(
      "添加Key",
      function( name, key )
        TXSSO2_Add2KeyChain( name, key:str2hexs() );
      end,
      "Key名称", "Key串"
      )
    add_key = proto.prefs.add_key;
  end
  
  if add_pskey ~= proto.prefs.add_pskey then
    new_dialog(
      "添加PsSaltKey",
      function( qq, ps )
        TXSSO2_SetPsSaltKey( qq, ps );
      end,
      "QQ号", "密码"
      )
    add_pskey = proto.prefs.add_pskey;
  end
  
  if show_keychain ~= proto.prefs.show_keychain then
    --TextWindow在新版中不能为local，否则一闪而过
    keychain_window = TextWindow.new( "KeyChain数据" );
    for k, v in pairs( keychain ) do
      keychain_window:append( v:hex2str() .. "\t\t>> " .. k .. "\r\n" );
    end
    keychain_window:set_editable( false );
    show_keychain = proto.prefs.show_keychain;
  end
end

-------- -------- -------- --------
local Packet_PreFix = '\x02';
local Packet_SufFix = '\x03';

local function proto_chk( buf )
  --cPreFix、cSufFix、cMainVer、cSubVer、wCsCmdNo、wCsSenderSeq
  --至少有不小于0x10的数据
  local min_size = 1 + 1 + 1 + 1 + 2 + 2 + 0x10;
  local len = buf:len();
  if len < min_size then
    return false;
  end
  if buf:raw( 0, 1 ) ~= Packet_PreFix then
    return false;
  end
  if buf:raw( len - 1, 1 ) ~= Packet_SufFix then
    return false;
  end
  return true;
end

local CsCmdNo = require "TXSSO2/CsCmdNo";
local dissectors = require "TXSSO2/Dissectors";

local function dissector_heuristic( buf, pkg, root )
  --端口限定
  local port = proto.prefs.port;
  if pkg.dst_port ~= port and pkg.src_port ~= port then
    return false;
  end

  --合法判定
  if not proto_chk( buf ) then
    return false;
  end
  
  pkg.cols.protocol:set( proto.name );

  local cmd = buf( 1 + 1 + 1, 2 ):uint();
  local cmds = CsCmdNo[ cmd ] or "???";
  local ss = string.format( "-%04X-%s-", cmd, cmds );
  --依据目标端口判定输入输出
  if pkg.dst_port == port then
    ss = "●" .. ss;
  else
    ss = "○" .. ss;
  end
  pkg.cols.info:set( ss );

  local t = root:add( proto, buf(), "Tencent SSO2 : " .. ss );

  local lvl = proto.prefs.alvl;
  if lvl == alvlS then
    return true;
  end
  --如果仅识别，后面的工作则无需继续

  --前缀输出
  dissectors.add( t, buf, 0,
    ">cPreFix B"
    );

  local ver = buf( 1, 2 ):uint();

  --对应SSO版本，或选择默认的解析函数组
  local func = dissectors[ ver ] or dissectors.other;
  if func then
    --对应CsCmdNo，或选择默认的解析函数组
    func = func[ cmd ] or func.other;
    if func then
      if pkg.src_port == port then
        func = func.recv;
      else
        func = func.send
      end
    else
      root:add( string.format( "Dissectors无对应CsCmdNo[%04X]，请添加之", cmd ) );
    end
  else
    root:add( string.format( "Dissectors无对应SSO版本[%04X]，请添加之", ver ) );
  end

  local data = buf( 1, buf:len() - 2 ):tvb();
  if func then
    local b, err = pcall( func, data, pkg, root, t );
    if not b then
      root:add( "解析失败 : " .. err );
      dissectors.add( t, data, 0, ">unsolved" );
    end
  else
    dissectors.add( t, data, 0, ">unsolved" );
  end

  --后缀输出
  dissectors.add( t, buf, buf:len() - 1,
    ">cSufFix B"
    );
  return true;
end

function proto.dissector( buf, pkg, root )
  if dissector_heuristic( buf, pkg, root ) then
    return buf:len();
  end
end

proto:register_heuristic( "udp", dissector_heuristic );

return proto;