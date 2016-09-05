--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> 0836
-------- -------- -------- --------

GetTGTGT
]=======]
local cmdno = 0x0836;

local dissectors = require "TXSSO2/Dissectors";

local proto = require "TXSSO2/Proto";

local keychain = require "TXSSO2/KeyChain";

local function PCQQSend( buf, pkg, root, t )
  local ver = buf( 0, 2 ):uint();
  local cmd = buf( 1 + 1, 2 ):uint();
  local seq = buf( 1 + 1 + 2, 2 ):uint();
  local qq = buf( 1 + 1 + 2 + 2, 4 ):uint();
  
  dissectors.ref_seq( root, pkg, buf, seq );

  TXSSO2_SetPsSaltKey( qq );    --用默认密码做一个KEY加入KeyChain，以便后面的解析

  local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer B",
    ">cSubVer B",
    ">wCsCmdNo W",
    ">wCsIOSeq W",
    ">dwUin D"
    );

  off = dissectors.add( t, buf, off,
    ">xxoo_a", 3,
    ">dwClientType D",
    ">dwPubNo D",
    ">xxoo_d",
    ">*SubVer W",
    ">*ECDH版本 W"
    );

  local bufDHPublicKey_size = buf( off, 2 ):uint();

  --local bufDHPublicKey = buf:raw( off + 2, bufDHPublicKey_size );
  --TXSSO2_Add2KeyChain( string.format( "s%04Xf%d_DHPublicKey", seq, pkg.number ), bufDHPublicKey );

  local key = buf:raw( off + 2 + bufDHPublicKey_size + 4, 0x10 );
  TXSSO2_Add2KeyChain( TXSSO2_MakeKeyName( cmd, seq, pkg.number ), key );
  
  off = dissectors.add( t, buf, off,
    ">bufDHPublicKey wxline_bytes",
    ">*dwCsCmdCryptKeySize D",
    ">bufCsPrefix", 0x10
    );
    
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

  local tt = t:add( proto, buf( 0, 0xA ), "bufPacketHeader");
  local off = dissectors.add( tt, buf, 0,
    ">cMainVer B",
    ">cSubVer B",
    ">wCsCmdNo W",
    ">wCsIOSeq W",
    ">dwUin D"
    );

  off = dissectors.add( t, buf, off,
    ">xxoo_a", 3
    );
    
  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Response" );

  if not tt then
    return;
  end

  buf = ByteArray.new( ds, true ):tvb( "Decode1" );
  
  --做二次解密尝试，注意，只是尝试，因为要考虑密码错误返回的情况，此时，并不需要二次解密
  local ttt, ds = dissectors.try_decrypt( tt, pkg, buf, "GeneralCodec_Response", true );
  tt = ttt or tt;

  if ttt then
    buf = ByteArray.new( ds, true ):tvb( "Decode2" );
  end

  local off = dissectors.add( tt, buf, 0, ">cResult B" );
  
  return dissectors.dis_tlv( buf( off ):tvb(), pkg, root, tt );
end

dissectors.other = dissectors.other or {};
dissectors.other[cmdno] = dissectors.other[cmdno] or {};
dissectors.other[cmdno].send = dissectors.other[cmdno].send or PCQQSend;
dissectors.other[cmdno].recv = dissectors.other[cmdno].recv or PCQQRecv;