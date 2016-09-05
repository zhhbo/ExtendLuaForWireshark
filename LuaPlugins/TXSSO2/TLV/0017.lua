--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0017
-------- -------- -------- --------

SSO2::TLV_ClientInfo_0x17
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0017] = function( buf, pkg, root, t )
  local off = 0;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off,
      ">dwServerTime    xdate",
      ">ClientWanIP     ipv4_port",
      ">UnknowBuf       wxline_bytes"
      );
  end
  return off;
end