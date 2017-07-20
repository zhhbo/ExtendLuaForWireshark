--[=======[
-------- -------- -------- --------
         �Զ����ʽ��
-------- -------- -------- --------
--FormatEx�ṩͨ�õ��Զ����ʽ����������TreeAddExʹ��
]=======]

--[=======[
��
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
                        0.0.0.0         //��hostname�޷�ȷ��ʱ����ʾ
  ipv4_port;          --hostname:port(0.0.0.0:0)    6 byte
                        0.0.0.0:0       //��hostname�޷�ȷ��ʱ����ʾ
                        
  xipv4_port;         --hostname:port(0.0.0.0:0)    6 byte
                        0.0.0.0:0       //��hostname�޷�ȷ��ʱ����ʾ
                                        //�ֽ�˳�����ڱ�ʾport��ע��ip���ֽ���port�෴
  float;              --0.0             //���Ӵ�С��
  string;             --00000           //size == -1ʱ��ȡʣ����������
                                        //ע�����-1�����ฺֵ������
                                        //ע����ֵ����tvb��ΧҲ����
                                        //ע��size==0�����Թ������һ��tree
  bytes;              --000000          //size == -1ʱ��ȡʣ����������

  stringz;                              //������ָ��size����\0�ض�(����\0)������ȡʣ����������

  //xline��ʾhead�����������С
  bxline_string;      bline_string;                 1 + N byte
  wxline_string;      wline_string;                 2 + N byte
  dxline_string;      dline_string;                 4 + N byte

  bxline_bytes;       bline_bytes;                  1 + N byte
  wxline_bytes;       wline_bytes;                  2 + N byte
  dxline_bytes;       dline_bytes;                  4 + N byte

  xdate               --0000/00/00 00:00:00         4 byte
  xtime               --00day 00:00:00              4 byte
  xcapacity           --0.00T|0.00G|0.00M|0.00K|0.00B       N byte��ָ��

  ע�⣬��string��bytes�������ݹ���ʱ���᷵�ص��������ݽضϽ������0000...
]=======]

local function LimitString( str )
  if #str > 0x2C then
    str = str:sub( 1, 0x28 ) .. "...";
  end
  return str;
end

FormatEx = { };
function FormatEx.uint8( tvb, off )
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

function FormatEx.int8( tvb, off )
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
    sss = tvb( off + 3, 1 ):uint() .. '.' ..
          tvb( off + 2, 1 ):uint() .. '.' ..
          tvb( off + 1, 1 ):uint() .. '.' ..
          tvb( off + 0, 1 ):uint();
  else
    ss = tostring( tvb( off, 4 ):ipv4() );
    sss = tvb( off + 0, 1 ):uint() .. '.' ..
          tvb( off + 1, 1 ):uint() .. '.' ..
          tvb( off + 2, 1 ):uint() .. '.' ..
          tvb( off + 3, 1 ):uint();
  end
  local mm = ss:gsub( "[%.%d]", "" );
  if mm ~= "" then
    ss = ss .. '(' .. sss .. ')';
  end
  return ss, 4;
end

function FormatEx.ipv4_port( tvb, off, size, func, root )
  local ss, sss, pp;
  if func and func ~= root.add then
    ss = tostring( tvb( off, 4 ):le_ipv4() );
    sss = tvb( off + 3, 1 ):uint() .. '.' ..
          tvb( off + 2, 1 ):uint() .. '.' ..
          tvb( off + 1, 1 ):uint() .. '.' ..
          tvb( off + 0, 1 ):uint();
    pp = tvb( off + 4, 2 ):le_uint();
  else
    ss = tostring( tvb( off, 4 ):ipv4() );
    sss = tvb( off + 0, 1 ):uint() .. '.' ..
          tvb( off + 1, 1 ):uint() .. '.' ..
          tvb( off + 2, 1 ):uint() .. '.' ..
          tvb( off + 3, 1 ):uint();
    pp = tvb( off + 4, 2 ):uint();
  end
  local mm = ss:gsub( "[%.%d]", "" );
  ss = ss .. ':' .. pp;
  if mm ~= "" then
    ss = ss .. '(' .. sss .. ':' .. pp .. ')';
  end
  return ss, 4 + 2;
end

function FormatEx.xipv4_port( tvb, off, size, func, root )
  local ss, sss, pp;
  if func and func ~= root.add then
    ss = tostring( tvb( off, 4 ):ipv4() );
    sss = tvb( off + 0, 1 ):uint() .. '.' ..
          tvb( off + 1, 1 ):uint() .. '.' ..
          tvb( off + 2, 1 ):uint() .. '.' ..
          tvb( off + 3, 1 ):uint();
    pp = tvb( off + 4, 2 ):le_uint();
  else
    ss = tostring( tvb( off, 4 ):le_ipv4() );
    sss = tvb( off + 3, 1 ):uint() .. '.' ..
          tvb( off + 2, 1 ):uint() .. '.' ..
          tvb( off + 1, 1 ):uint() .. '.' ..
          tvb( off + 0, 1 ):uint();
    pp = tvb( off + 4, 2 ):uint();
  end
  local mm = ss:gsub( "[%.%d]", "" );
  ss = ss .. ':' .. pp;
  if mm ~= "" then
    ss = ss .. '(' .. sss .. ':' .. pp .. ')';
  end
  return ss, 4 + 2;
end

function FormatEx.float( tvb ,off )
  return tvb( off, 4 ):float(), 4;
end

function FormatEx.string( tvb ,off, size )
  local ss;
  if size == nil then
    ss = tvb:raw( off );
  else
    ss = tvb:raw( off, size );
  end

  return ss, #ss, LimitString( ss );
end

function FormatEx.bytes( tvb, off, size )
  local ss, size = FormatEx.string( tvb ,off, size );
  ss = hex2str( ss );

  return ss, size, LimitString( ss );
end

function FormatEx.stringz( tvb, off )
  local e = off;
  local len = tvb:len();
  while e < len do
    if tvb( e, 1 ):uint() == 0 then
      local size = e - off;
      return tvb:raw( off, size ), size + 1; 
    end
    e = e + 1;
  end
  local size = len - off;
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

  local ss = tvb:raw( off + ls, size - x );;

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

  local ss = tvb:raw( off + ls, size - x ):hex2str();

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

  local s = t % 60;   t = math.floor( t / 60 );
  local m = t % 60;   t = math.floor( t / 60 );
  local h = t % 24;   t = math.floor( t / 24 );

  return t .. "day " .. h .. ":" .. m .. ":" .. s, 4;
end

function FormatEx.xcapacity( tvb, off, size, func, root )
  local x;
  if func and func ~= root.add then
    x = tvb( off, size ):le_uint64();
    local f = UInt64.new( 1 );      --�����Ͱ汾wiresharkֻ���8 byte��BUG
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
  return  string.format( "%.2f", x:lower() ) .. " B", size; 
end