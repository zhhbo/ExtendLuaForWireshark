--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0006
-------- -------- -------- --------

SSO2::TLV_TGTGT_0x6
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x0006] = function( buf, pkg, root, t )
  local tt, ds = dissectors.try_decrypt( t, pkg, buf, "TGTGT" );

  if not tt then
    return;
  end
  local oo = buf:len();

  buf = ByteArray.new( ds, true ):tvb( "TGTGT" );

  local ver = buf( 4, 2 ):uint();
  local off = 0;
  
  if ver == 0x0002 then
    off = dissectors.add( tt, buf, off,
      ">*dwRand随机值     D",
      ">wTlvVer           W",
      ">dwUin             D",
      ">dwSSOVersion      D",
      ">dwServiceId       D",
      ">dwClientVer       D",
      ">*const_0          W",
      ">bRememberPwdLogin B",
      ">bufPsMD5",        0x10,
      ">dwServerTime      xdate",
      ">*const_0          bytes", 0xD,
      ">dwClientWanIP     D",
      ">dwISP             D",
      ">dwIDC             D",
      ">bufComputerID     wxline_bytes"
      );
    local key = buf:raw( off, 0x10 );
    TXSSO2_Add2KeyChain( string.format( "f%d_TGTGTKey", pkg.number ), key );
    off = dissectors.add( tt, buf, off, ">bufTGTGTKey", 0x10 );
  end
  if off < buf:len() then
    TreeAddEx( fieldsex, t, buf, off, ">unsolved" );
  end
  return oo;
end