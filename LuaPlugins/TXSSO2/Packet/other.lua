--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> Other
-------- -------- -------- --------

Other
]=======]
local dissectors = require "TXSSO2/Dissectors";

local proto = require "TXSSO2/Proto";

local function PCQQCommonSend( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();
  
  dissectors.ref_seq( root, pkg, buf, seq );

  --输出包头
  local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer    B",
    ">cSubVer     B",
    ">wCsCmdNo    W",
    ">wCsIOSeq    W",
    ">dwUin       D"
    );
  --输出中段信息
  off = dissectors.add( t, buf, off,
    ">xxoo_a",    3,
    ">dwClientType D",
    ">dwPubNo     D"
    );

  --剩余的数据，尝试解密
  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Request" );

  if not tt then
    return buf, t;
  end

  buf = ByteArray.new( ds, true ):tvb( "Decode" );
  return buf, tt;
end

local function PCQQCommonRecv( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();
  
  dissectors.ref_seq( root, pkg, buf, seq );

  --包头
  local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer      B",
    ">cSubVer       B",
    ">wCsCmdNo      W",
    ">wCsIOSeq      W",
    ">dwUin         D"
    );
    --中段信息
  off = dissectors.add( t, buf, off,
    ">xxoo_a",      3
    );
    
  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Response" );

  if not tt then
    return buf, t;
  end

  buf = ByteArray.new( ds, true ):tvb( "Decode" );
  
  return buf, tt;
end

local function PCQQSend( buf, pkg, root, t )
  local data, tt = PCQQCommonSend( buf, pkg, root, t );
  dissectors.add( tt, data, 0, ">unsolved" );
end

local function PCQQRecv( buf, pkg, root, t )
  local data, tt = PCQQCommonRecv( buf, pkg, root, t );
  dissectors.add( tt, data, 0, ">unsolved" );
end


local function GameQQCommonSend( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();
  
  dissectors.ref_seq( root, pkg, buf, seq );

  --输出包头
  local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer    B",
    ">cSubVer     B",
    ">wCsCmdNo    W",
    ">wCsIOSeq    W",
    ">dwUin       D"
    );

  --剩余的数据，尝试解密
  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Request" );

  if not tt then
    return buf, t;
  end

  buf = ByteArray.new( ds, true ):tvb( "Decode" );
  return buf, tt;
end

local function GameQQCommonRecv( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();
  
  dissectors.ref_seq( root, pkg, buf, seq );

  --包头
  local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer      B",
    ">cSubVer       B",
    ">wCsCmdNo      W",
    ">wCsIOSeq      W"
    );
    
  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Response" );

  if not tt then
    return buf, t;
  end

  buf = ByteArray.new( ds, true ):tvb( "Decode" );
  
  return buf, tt;
end

local function GameQQSend( buf, pkg, root, t )
  local data, tt = GameQQCommonSend( buf, pkg, root, t );
  dissectors.add( tt, data, 0, ">unsolved" );
end

local function GameQQRecv( buf, pkg, root, t )
  local data, tt = GameQQCommonRecv( buf, pkg, root, t );
  dissectors.add( tt, data, 0, ">unsolved" );
end

dissectors.other = dissectors.other or {};
dissectors.other.other = dissectors.other.other or {};
dissectors.other.other.commonsend = dissectors.other.other.commonsend or PCQQCommonSend;
dissectors.other.other.commonrecv = dissectors.other.other.commonrecv or PCQQCommonRecv;
dissectors.other.other.send = dissectors.other.other.send or PCQQSend;
dissectors.other.other.recv = dissectors.other.other.recv or PCQQRecv;

dissectors[0x5006] = dissectors[0x5006] or {};
dissectors[0x5006].other = dissectors[0x5006].other or {};
dissectors[0x5006].other.commonsend = dissectors[0x5006].other.commonsend or GameQQCommonSend;
dissectors[0x5006].other.commonrecv = dissectors[0x5006].other.commonrecv or GameQQCommonRecv;
dissectors[0x5006].other.send = dissectors[0x5006].other.send or GameQQSend;
dissectors[0x5006].other.recv = dissectors[0x5006].other.recv or GameQQRecv;