--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> KeyChain
-------- -------- -------- --------

新建全局函数TXSSO2_Add2KeyChain，用于向KeyChain添加命名的Key

返回常量表

KeyChain中的KeyName不允许重复
KeyChain中的Key参与解密时，无论长度如何，都将固定为0x10，长度不足，以\0补齐，长度过长，则截断
KeyChain只允许添加，不允许删除。
默认KeyChain初始时只存在两个默认的ECDH KEY。这两个KEY对于插件，是【永久存在】的。
所有使用接口向KeyChain添加的KEY都是临时的，只对【当前WireShark进程】有效。
如果你需要某KEY永久生效，请自行修改源脚本。
]=======]
local keychain = {};

--提供函数用于将KEY加入KeyChain
function TXSSO2_Add2KeyChain( key_name, key )
  if not key_name then
    return error( "加入KeyChain请指定KeyName" );
  end
  if type( key_name ) ~= "string" then
    return error( "加入KeyChain的KeyName必须为string类型" );
  end
  if keychain[ key_name ] then
    if keychain[ key_name ] ~= key then
      return error( "加入KeyChain时KeyName[" .. key_name .. "]重复" );
    else
      return;
    end
  end
  if type( key ) ~= "string" then
    return error( "加入KeyChain的Key必须为string类型" );
  end
  if #key < 0x10 then
    key = key .. string.rep( '\x00', 0x10 - #key );
  end
  if #key > 0x10 then
    key = key:sub( 1, 0x10 );
  end
  keychain[ key_name ] = key;
end

function TXSSO2_MakeKeyName( CsCmdNo, Seq, FrameNum )
  return string.format( "c%04X_s%04X_f%u", CsCmdNo, Seq, FrameNum );
end

function TXSSO2_AnalysisKeyName( KeyName )
  return KeyName:match( "c(%x%x%x%x)_s(%x%x%x%x)_f(%d+)" );
end

function TXSSO2_SetPsSaltKey( qq, ps )
  if type( qq ) == "string" then
    qq = tonumber( qq );
  end
  ps = ps or "Qq185131606";     --默认密码
  local pssaltmd5 = netline:new();
  pssaltmd5:sa( ps:md5() );
  pssaltmd5:sd( 0 );
  pssaltmd5:sd( qq );
  TXSSO2_Add2KeyChain( string.format( "PsSaltMd5_%u_%s", qq, ps ), pssaltmd5.line:md5() );
end

--预先添加默认的ECDH Key
local keys = require "TXSSO2/ECDHKey";
local publickey, sharekey = unpack( keys );

TXSSO2_Add2KeyChain( "Default ECDH Public Key", publickey );
TXSSO2_Add2KeyChain( "Default ECDH Share Key", sharekey );

--这样算是protect技术，即保护表不被外部修改，但内部允许修改
return setmetatable(
  {},
  {
  __index = keychain;
  __pairs = function( t )
    return next, keychain, nil;
  end;
  __newindex = function()
    return error( "KeyChain禁止外部修改，请使用[TXSSO2_Add2KeyChain]函数添加" );
  end;
  }
  );