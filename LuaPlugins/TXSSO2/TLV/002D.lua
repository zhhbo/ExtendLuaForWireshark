--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 002D
-------- -------- -------- --------

TLV_LocalIP
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x002D] = function( buf, pkg, root, t )
  local off = 0;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off,
      ">dwLocalIP D"
      );
  end
  return off;
end