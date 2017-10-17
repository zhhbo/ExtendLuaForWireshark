--[=======[
-------- -------- -------- --------
         自定义格式化
-------- -------- -------- --------
--FormatEx提供通用的自定义格式化操作，被TreeAddEx使用
]=======]

--[=======[
●
  uint8;              --0x00(0)                     1 byte
  uint16;             --0x0000(0)                   2 byte
  uint24;             --0x000000(0)                 3 byte
  uint32;             --0x00000000(0)               4 byte
  uint64;             --0x0000000000000000(0)       8 byte
  int8;               --0x00(0)                     1 byte
  int16;              --0x0000(0)                   2 byte
  int24;              --0x000000(0)                 3 byte
  int32;              --0x00000000(0)               4 byte
  int64;              --0x0000000000000000(0)       8 byte

  bool;               --true|false                  1 byte
  ipv4;               --hostname(0.0.0.0)           4 byte
                        0.0.0.0         //当hostname无法确定时，显示
  ipv4_port;          --hostname:port(0.0.0.0:0)    6 byte
                        0.0.0.0:0       //当hostname无法确定时，显示
                        
  xipv4_port;         --hostname:port(0.0.0.0:0)    6 byte
                        0.0.0.0:0       //当hostname无法确定时，显示
                                        //字节顺序用于标示port，注意ip的字节与port相反
  float;              --0.0             //无视大小端
  string;             --00000           //size == -1时，取剩余所有数据
                                        //注意除了-1，其余负值将出错
                                        //注意正值超过tvb范围也出错
                                        //注意size==0，可以故意插入一个tree
  bytes;              --000000          //size == -1时，取剩余所有数据

  stringz;                              //不接受指定size，遇\0截断(包含\0)，否则取剩余所有数据

  //xline表示head不包含自身大小
  bxline_string;      bline_string;                 1 + N byte
  wxline_string;      wline_string;                 2 + N byte
  dxline_string;      dline_string;                 4 + N byte

  bxline_bytes;       bline_bytes;                  1 + N byte
  wxline_bytes;       wline_bytes;                  2 + N byte
  dxline_bytes;       dline_bytes;                  4 + N byte

  xdate               --0000/00/00 00:00:00         4 byte
  xtime               --00day 00:00:00              4 byte
  xcapacity           --0.00T|0.00G|0.00M|0.00K|0.00B       N byte需指定

  注意，当string或bytes类型数据过大时，会返回第三个数据截断结果，如0000...
]=======]

local function LimitString( str )
  if #str > 0x2C then
    str = str:sub( 1, 0x28 ) .. "...";
  end
  return str;
end

FormatEx = { };
function FormatEx.uint8( tvb, off, size, func, root )
  local v = tvb( off, 1 ):uint();
  return string.format( "0x%02X(%u)", v, v ), 1;
end
function FormatEx.uint16( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 2 ):le_uint();
  else
    v = tvb( off, 2 ):uint();
  end
  return string.format( "0x%04X(%u)", v, v ), 2;
end
function FormatEx.uint24( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 3 ):le_uint();
  else
    v = tvb( off, 3 ):uint();
  end
  return string.format( "0x%06X(%u)", v, v ), 3;
end
function FormatEx.uint32( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 4 ):le_uint();
  else
    v = tvb( off, 4 ):uint();
  end
  return string.format( "0x%08X(%u)", v, v ), 4;
end
function FormatEx.uint64( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 8 ):le_uint64();
  else
    v = tvb( off, 8 ):uint64();
  end
  return "0x" .. v:tohex() .. '(' .. v .. ')', 8;
end

function FormatEx.int8( tvb, off, size, func, root )
  local v = tvb( off, 1 ):int();
  return string.format( "0x%02X(%d)", v, v ), 1;
end
function FormatEx.int16( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 2 ):le_int();
  else
    v = tvb( off, 2 ):int();
  end
  return string.format( "0x%04X(%d)", v, v ), 2;
end
function FormatEx.int24( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 3 ):le_int();
  else
    v = tvb( off, 3 ):int();
  end
  return string.format( "0x%06X(%d)", v, v ), 3;
end
function FormatEx.int32( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 4 ):le_int();
  else
    v = tvb( off, 4 ):int();
  end
  return string.format( "0x%08X(%d)", v, v ), 4;
end
function FormatEx.int64( tvb, off, size, func, root )
  local v;
  if func and func ~= root.add then
    v = tvb( off, 8 ):le_int64();
  else
    v = tvb( off, 8 ):int64();
  end
  return "0x" .. v:tohex() .. '(' .. v .. ')', 8;
end

function FormatEx.bool( tvb, off )
  local v = tvb( off, 1 ):int();
  if v == 0 then
    return "false", 1;
  end
  return "true", 1;
end

function FormatEx.ipv4( tvb, off, size, func, root )
  local ss, sss;
  if func and func ~= root.add then
    ss = tostring( tvb( off, 4 ):le_ipv4() );
    sss = string.format( "%d.%d.%d.%d", 
          tvb( off + 3, 1 ):uint(),
          tvb( off + 2, 1 ):uint(),
          tvb( off + 1, 1 ):uint(),
          tvb( off + 0, 1 ):uint());
  else
    ss = tostring( tvb( off, 4 ):ipv4() );
    sss = string.format( "%d.%d.%d.%d", 
          tvb( off + 0, 1 ):uint(),
          tvb( off + 1, 1 ):uint(),
          tvb( off + 2, 1 ):uint(),
          tvb( off + 3, 1 ):uint());
  end
  if ss:gsub( "[%.%d]", "" ) ~= "" then
    ss = ss .. '(' .. sss .. ')';
  end
  return ss, 4;
end

function FormatEx.ipv4_port( tvb, off, size, func, root )
  local ss, sss, pp;
  if func and func ~= root.add then
    ss = tostring( tvb( off, 4 ):le_ipv4() );
    sss = string.format( "%d.%d.%d.%d", 
          tvb( off + 3, 1 ):uint(),
          tvb( off + 2, 1 ):uint(),
          tvb( off + 1, 1 ):uint(),
          tvb( off + 0, 1 ):uint());
    pp = tvb( off + 4, 2 ):le_uint();
  else
    ss = tostring( tvb( off, 4 ):ipv4() );
    sss = string.format( "%d.%d.%d.%d", 
          tvb( off + 0, 1 ):uint(),
          tvb( off + 1, 1 ):uint(),
          tvb( off + 2, 1 ):uint(),
          tvb( off + 3, 1 ):uint());
    pp = tvb( off + 4, 2 ):uint();
  end
  ss = string.format( "%s:%d", ss, pp );
  if ss:gsub( "[%.%d%:]", "" ) ~= "" then
    ss = string.format( "%s(%s:%d)", ss, sss, pp );
  end
  return ss, 4 + 2;
end

function FormatEx.xipv4_port( tvb, off, size, func, root )
  local ss, sss, pp;
  if func and func ~= root.add then
    ss = tostring( tvb( off, 4 ):ipv4() );
    sss = string.format( "%d.%d.%d.%d", 
          tvb( off + 0, 1 ):uint(),
          tvb( off + 1, 1 ):uint(),
          tvb( off + 2, 1 ):uint(),
          tvb( off + 3, 1 ):uint());
    pp = tvb( off + 4, 2 ):le_uint();
  else
    ss = tostring( tvb( off, 4 ):le_ipv4() );
    sss = string.format( "%d.%d.%d.%d", 
          tvb( off + 3, 1 ):uint(),
          tvb( off + 2, 1 ):uint(),
          tvb( off + 1, 1 ):uint(),
          tvb( off + 0, 1 ):uint());
    pp = tvb( off + 4, 2 ):uint();
  end
  ss = string.format( "%s:%d", ss, pp );
  if ss:gsub( "[%.%d%:]", "" ) ~= "" then
    ss = string.format( "%s(%s:%d)", ss, sss, pp );
  end
  return ss, 4 + 2;
end

function FormatEx.float( tvb, off, size, func, root )
  return tvb( off, 4 ):float(), 4;
end

function FormatEx.string( tvb, off, size, func, root )
  local ss;
  if size == nil then
    ss = tvb:raw( off );
  else
    ss = tvb:raw( off, size );
  end

  return ss, #ss, LimitString( ss );
end

function FormatEx.bytes( tvb, off, size, func, root )
  local ss, size = FormatEx.string( tvb ,off, size );
  ss = bin2hex( ss );

  return ss, size, LimitString( ss );
end

function FormatEx.stringz( tvb, off, size, func, root )
  local e = off;
  local len = tvb:len();
  local size = len - off;
  for i = off, len - 1 do
    if tvb( i, 1 ):uint() == 0 then
      size = i - off + 1;
      break;
    end
  end
  local ss = tvb:raw( off, size );
  return ss, size, LimitString( ss );
end

local function get_line_string( ls, x, tvb, off, size, func, root )
  local fmt;
  if x then
    x = 0;
    fmt = "(%0" .. ls * 2 .. "x)";
  else
    x = ls;
    fmt = "[%0" .. ls * 2 .. "x]";
  end
  local size;
  if func and func ~= root.add then
    size = tvb( off, ls ):le_uint();
  else
    size = tvb( off, ls ):uint();
  end

  local ss = tvb:raw( off + ls, size - x );

  return ss, size + ls - x, string.format( fmt, #ss ) .. LimitString( ss );
end

function FormatEx.bxline_string( tvb, off, size, func, root )
  return get_line_string( 1, true, tvb, off, size, func, root );
end
function FormatEx.bline_string( tvb, off, size, func, root )
  return get_line_string( 1, false, tvb, off, size, func, root );
end
function FormatEx.wxline_string( tvb, off, size, func, root )
  return get_line_string( 2, true, tvb, off, size, func, root );
end
function FormatEx.wline_string( tvb, off, size, func, root )
  return get_line_string( 2, false, tvb, off, size, func, root );
end
function FormatEx.dxline_string( tvb, off, size, func, root )
  return get_line_string( 4, true, tvb, off, size, func, root );
end
function FormatEx.dline_string( tvb, off, size, func, root )
  return get_line_string( 4, false, tvb, off, size, func, root );
end

local function get_line_bytes( ls, x, tvb, off, size, func, root )
  local fmt;
  if x then
    x = 0;
    fmt = "(%0" .. ls * 2 .. "x)";
  else
    x = ls;
    fmt = "[%0" .. ls * 2 .. "x]";
  end
  local size;
  if func and func ~= root.add then
    size = tvb( off, ls ):le_uint();
  else
    size = tvb( off, ls ):uint();
  end

  local ss = bin2hex( tvb:raw( off + ls, size - x ) );

  return ss, size + ls - x, string.format( fmt, size - x ) .. LimitString( ss );
end

function FormatEx.bxline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 1, true, tvb, off, size, func, root );
end
function FormatEx.bline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 1, false, tvb, off, size, func, root );
end
function FormatEx.wxline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 2, true, tvb, off, size, func, root );
end
function FormatEx.wline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 2, false, tvb, off, size, func, root );
end
function FormatEx.dxline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 4, true, tvb, off, size, func, root );
end
function FormatEx.dline_bytes( tvb, off, size, func, root )
  return get_line_bytes( 4, false, tvb, off, size, func, root );
end

function FormatEx.xdate( tvb, off, size, func, root )
  local t;
  if func and func ~= root.add then
    t = tvb( off, 4 ):le_uint();
  else
    t = tvb( off, 4 ):uint();
  end
  return os.date( "%Y/%m/%d %H:%M:%S", t ), 4;
end

function FormatEx.xtime( tvb, off, size, func, root )
  local t;
  if func and func ~= root.add then
    t = tvb( off, 4 ):le_uint();
  else
    t = tvb( off, 4 ):uint();
  end

  local s = t % 60;   t = t // 60;
  local m = t % 60;   t = t // 60;
  local h = t % 24;   t = t // 24;

  return string.format( "%dday %d:%d:%d", t, h, m, s), 4;
end

function FormatEx.xcapacity( tvb, off, size, func, root )
  local x;
  if func and func ~= root.add then
    x = tvb( off, size ):le_uint64();
    local f = UInt64.new( 1 );      --修正低版本wireshark只会读8 byte的BUG
    for k = 1, size do
      f = f * UInt64.new( 0x100 );
    end
    x = x % f;
  else
    x = tvb( off, size ):uint64();
    for k = 1, 8 - size do
      x = x / UInt64.new( 0x100 );
    end
  end

  local t = x:higher() / 0x100;
  if t >= 1 then
    return string.format( "%.2f", t ) .. " TB", size; 
  end

  local g = ( x:higher() * 0x10 / 4 ) + ( x:lower() / 0x40000000 );
  if g > 1 then
    return  string.format( "%.2f", g ) .. " GB", size; 
  end

  local m = x:lower() / 0x100000;
  if m > 1 then
    return  string.format( "%.2f", m ) .. " MB", size; 
  end

  local k = x:lower() / 0x400;
  if k > 1 then
    return  string.format( "%.2f", k ) .. " KB", size; 
  end
  return  string.format( "%d", x:lower() ) .. " B", size; 
end