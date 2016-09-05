--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0114
-------- -------- -------- --------

SSO2::TLV_DHParams_0x114
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0114] = function( buf, pkg, root, t )
  local off = 0;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0102 then
    off = dissectors.add( t, buf, off,
      ">bufDHPublicKey wxline_bytes"
      );
  end
  return off;
end