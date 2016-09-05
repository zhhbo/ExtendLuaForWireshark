--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 001A
-------- -------- -------- --------

SSO2::TLV_GTKeyTGTGTCryptedData_0x1a
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x001A] = function( buf, pkg, root, t )
  local tt, ds = dissectors.try_decrypt( t, pkg, buf, "GTKeyTGTGTCryptedData" );

  if not tt then
    return;
  end
  local oo = buf:len();

  buf = ByteArray.new( ds, true ):tvb( "GTKeyTGTGTCryptedData" );

  dissectors.dis_tlv( buf, pkg, root, tt );
  return oo;
end