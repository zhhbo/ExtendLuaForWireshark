--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> 0825
-------- -------- -------- --------

Ping
]=======]

local cmdno = 0x0825;

local dissectors = require "TXSSO2/Dissectors";

local proto = require "TXSSO2/Proto";

local function PCQQSend( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();

  dissectors.ref_seq( root, pkg, buf, seq );

  --输出包头
  local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer B",
    ">cSubVer B",
    ">wCsCmdNo W",
    ">wCsIOSeq W",
    ">dwUin D"
    );

  --输出中段信息
  off = dissectors.add( t, buf, off,
      ">xxoo_a", 3,
      ">dwClientType D",
      ">dwPubNo D",
      ">xxoo_d"
      );

  local key = buf:raw( off, 0x10 );
  TXSSO2_Add2KeyChain( TXSSO2_MakeKeyName( cmd, seq, pkg.number ), key );

  off = dissectors.add( t, buf, off,
      ">bufCsPrefix", 0x10
      );

  --剩余的数据，尝试解密
  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Request" );

  if not tt then
    return;
  end

  buf = ByteArray.new( ds, true ):tvb( "Decode" );
  return dissectors.dis_tlv( buf, pkg, root, tt );
end

local function PCQQRecv( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();

  dissectors.ref_seq( root, pkg, buf, seq );

  --包头
  local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer B",
    ">cSubVer B",
    ">wCsCmdNo W",
    ">wCsIOSeq W",
    ">dwUin D"
    );    
  --中段信息
  off = dissectors.add( t, buf, off,
    ">xxoo_a", 3
    );

  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Response" );

  if not tt then
    return;
  end
  
  buf = ByteArray.new( ds, true ):tvb( "Decode" );
  
  local off = dissectors.add( tt, buf, 0, ">cResult B" );

  return dissectors.dis_tlv( buf( off ):tvb(), pkg, root, tt );
end

local function GameQQSend( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();

  dissectors.ref_seq( root, pkg, buf, seq );

  --输出包头
  local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer B",
    ">cSubVer B",
    ">wCsCmdNo W",
    ">wCsIOSeq W",
    ">dwUin D"
    );

  local key = buf:raw( off, 0x10 );
  TXSSO2_Add2KeyChain( TXSSO2_MakeKeyName( cmd, seq, pkg.number ), key );

  off = dissectors.add( t, buf, off,
      ">bufCsPrefix", 0x10
      );

  --剩余的数据，尝试解密
  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Request" );

  if not tt then
    return;
  end

  buf = ByteArray.new( ds, true ):tvb( "Decode" );
  return dissectors.dis_tlv( buf, pkg, root, tt );
end

local function GameQQRecv( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();

  dissectors.ref_seq( root, pkg, buf, seq );

  --包头
  local tt = t:add( proto, buf( 0, 0x6 ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer B",
    ">cSubVer B",
    ">wCsCmdNo W",
    ">wCsIOSeq W"
    );

  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Response" );

  if not tt then
    return;
  end
  
  buf = ByteArray.new( ds, true ):tvb( "Decode" );
  
  local off = dissectors.add( tt, buf, 0, ">cResult B" );

  return dissectors.dis_tlv( buf( off ):tvb(), pkg, root, tt );
end

dissectors.other = dissectors.other or {};
dissectors.other[cmdno] = dissectors.other[cmdno] or {};
dissectors.other[cmdno].send = dissectors.other[cmdno].send or PCQQSend;
dissectors.other[cmdno].recv = dissectors.other[cmdno].recv or PCQQRecv;

dissectors[0x5006] = dissectors[0x5006] or {};
dissectors[0x5006][cmdno] = dissectors[0x5006][cmdno] or {};
dissectors[0x5006][cmdno].send = dissectors[0x5006][cmdno].send or GameQQSend;
dissectors[0x5006][cmdno].recv = dissectors[0x5006][cmdno].recv or GameQQRecv;

dissectors[0x5007] = dissectors[0x5007] or {};
dissectors[0x5007][cmdno] = dissectors[0x5007][cmdno] or {};
dissectors[0x5007][cmdno].send = dissectors[0x5007][cmdno].send or GameQQSend;
dissectors[0x5007][cmdno].recv = dissectors[0x5007][cmdno].recv or GameQQRecv;