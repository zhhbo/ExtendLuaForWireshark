--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Dissectors >>>> 0825
-------- -------- -------- --------

Ping
]=======]
local cmdno = 0x0828;

local dissectors = require "TXSSO2/Dissectors";

local proto = require "TXSSO2/Proto";

local function PCQQSend( buf, pkg, root, t )
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
    ">xxoo_a", 3,
    ">dwClientType D",
    ">dwPubNo D",
    ">xxoo_d",
    ">bufSession wxline_bytes"
    );
    
  local tt, ds = dissectors.try_decrypt( t, pkg, buf( off ):tvb(), "GeneralCodec_Request" );

  if not tt then
    return;
  end

  buf = ByteArray.new( ds, true ):tvb( "Decode" );
  return dissectors.dis_tlv( buf, pkg, root, tt );
end

require "TXSSO2/Packet/0825";

local PCQQRecv = dissectors.other[0x0825].recv;

dissectors.other = dissectors.other or {};
dissectors.other[cmdno] = dissectors.other[cmdno] or {};
dissectors.other[cmdno].send = dissectors.other[cmdno].send or PCQQSend;
dissectors.other[cmdno].recv = dissectors.other[cmdno].recv or PCQQRecv;