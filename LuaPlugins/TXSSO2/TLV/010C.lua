local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x010C] = function( buf, pkg, root, t )
  local off = 0;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    local key = buf:raw( off, 0x10 );
    TXSSO2_Add2KeyChain( string.format( "f%d_16byteSessionKey", pkg.number ), key );
    off = dissectors.add( t, buf, off,
      ">buf16byteSessionKey", 0x10,
      ">dwUin                 D",
      ">*客户端地址           ipv4_port",
      ">dwServerTime          xdate",
      ">xxoo_d",
      ">cPassSeqID            B",
      ">dwConnIP              D",
      ">dwReLoginConnIP       D",
      ">dwReLoginCtrlFlag     D",
      ">bufComputerIDSig      wxline_bytes",
      ">xxoo_s                bxline_bytes"
      );
    local ss, size = FormatEx.wxline_string( buf, off );
    local tt = t:add( proto, buf( off, size ), "Unknow" );
    local data = buf( off, size ):tvb();
    local oo = dissectors.add( tt, data, 2,
      ">xxoo_b",
      ">dwConnIP D",
      ">unsolved"
      );
    off = off + oo;
  end
  return off;
end