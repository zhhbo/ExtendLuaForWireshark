--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0109
-------- -------- -------- --------

SSO2::TLV_0xddReply_0x109
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0109] = function( buf, pkg, root, t )
  local off = 0;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    local key = buf:raw( off, 0x10 );
    TXSSO2_Add2KeyChain( string.format( "f%d_SessionKey", pkg.number ), key );
    off = dissectors.add( t, buf, off,
      ">bufSessionKey",   0x10,
      ">bufSession        wxline_bytes",
      ">bufPwdForConn     wxline_bytes",
      ">bufBill           wxline_bytes"
      );
  end
  return off;
end