--[=======[
-------- -------- -------- --------
         ProtoFieldEx����
-------- -------- -------- --------
]=======]

--[=======[
��
    table protofieldsex, table protofields
              ProtoFieldEx              (
                                        [ string proto_pre_fix, ]
                                        table fields
                                        );                                [-1|2, +2, v]
        --�����Զ������ʽ����Field��
        --���ص�һ����������TreeAddEx���ʹ�ã���Ԫ�����
          {
          ["__fmt"] = fmt;
          [short_addr] = { type, field, exfunc },
          ...
          }
        --���صڶ���������proto.fields�ĸ�ֵ
          {
          [short_addr] = field,
          ...
          }
        --����proto_pre_fix�������abbrǰ׺��ǿ�ҽ������֮��
        --fields�Ĺ������£�
          {
            { func,         short_abbr,     name,         ... },
            ...
          };
          name����Ϊnil����ʱ��nameĬ��ʹ��short_abbr������
        --����Ԥ��ɨ��ȫ����ȡshort_abbr��name������󳤶ȣ��趨�����ʽ����������fix_name
          "%-##s    %-##s    "
        --���ڱ���ÿ��Ԫ�أ�������Ϊ֮����
            field = ProtoField[ func ]( proto_pre_fix .. short_abbr, fix_name, ... );
          ��funcδ��ʶ��ʱ��Ĭ��ʹ��string
          ����funcΪFormatEx���Ӻ�����������������Ӻ�����ʱ��Ĭ����Ϊstring
          ����TreeAddExʱ������ͬ
          �磺
          { "wxline_string", "wxline_msg", "MSG" }  --wxline_msg�������string
        --func���Ӵ�д��һ��ת����Сд��ʽ
        --�����Զ��ڱ�ǰ�������Ĭ��Ԫ��
          {
            { "uint8",      "xxoo_b",     "Byte",    base.HEX_DEC },
            { 'uint16',     "xxoo_w",     "Word",    base.HEX_DEC },
            { 'uint32',     "xxoo_d",     "Dword",   base.HEX_DEC },
            { 'uint64',     "xxoo_q",     "Qword",   base.HEX_DEC },
            { 'bytes',      "xxoo_a",     "Array"                 },
            { "string",     "xxoo_s",     "String"                },
          };
        --��Ԫ��====������֮===
        --!!!!��������fix_nameʱ����UTF8��ʽ�����ַ�����Ҫ��short_abbr��name����ΪUTF8!!!!
        --fields��func�����д��          
          {
          b   = "uint8",
          w   = "uint16",
          d   = "uint32",
          q   = "uint64",
          a   = "bytes",
          s   = "string",
          }
]=======]
--�˱����ڴ����д
local ProtoFieldShort =
  {
  b   = "uint8",
  w   = "uint16",
  d   = "uint32",
  q   = "uint64",
  a   = "bytes",
  s   = "string",
  };

function ProtoFieldEx( arg1, arg2 )
  --�����ת�ƽ�����Ϊ���ڷ�wireshark�����³�ʼ��ʱ������
  local ProtoFieldDefault =
    {
      { "uint8",      "xxoo_b",     "Byte",       base.HEX_DEC },
      { 'uint16',     "xxoo_w",     "Word",       base.HEX_DEC },
      { 'uint32',     "xxoo_d",     "Dword",      base.HEX_DEC },
      { 'uint64',     "xxoo_q",     "Qword",      base.HEX_DEC },
      { 'bytes',      "xxoo_a",     "Array"                    },
      { "string",     "xxoo_s",     "String"                   },
    };
  --����ʶ��
  local pre_fix, fields;
  if type( arg2 ) == "table" then
    pre_fix = arg1;
    fields = arg2;
  else
    fields = arg1;
    pre_fix = arg2;
  end
  pre_fix = pre_fix or "";

  --���ƣ���������ԭʼfields����޸�
  local fs = {};
  for k, t in pairs( fields ) do
    fs[ k ] = { table.unpack( t ) };
  end
  fields = fs;

  --����Ĭ�ϱ�
  for _, tb in pairs( ProtoFieldDefault ) do
    table.insert( fields, 1, tb );
  end

  --ȥ���ظ���abbr_name�����ص�����£������һ��Ϊ׼
  local fs = {};
  for k, tb in pairs( fields ) do
    fs[ tb[ 2 ] ] = k;
  end
  
  --�Ȼ�ȡabbr��name����󳤶ȣ����ڶ�����ʾ
  local abbr_max = 16;
  local name_max = 16;

  for _, k in pairs( fs ) do
    local arg = fields[ k ];
    if #arg[ 2 ] > abbr_max then        --abbr����Ҫ��
      abbr_max = #arg[ 2 ];
    end
    if arg[ 3 ] then                    --name����û��
      arg[ 3 ] = utf82s( arg[ 3 ] );
      if #arg[ 3 ] > name_max then      --����utf8��ascii�ĳ��Ȳ���
        name_max = #arg[ 3 ];
      end
    end
  end
  if name_max < abbr_max then           --name����󳤶ȱ��벻С��abbr
    name_max = abbr_max;
  end
  local fmt = "%-" .. abbr_max .. "s    %-" .. name_max .. "s    ";
  
  local protofieldsex = { ["__fmt"] = fmt .. ": " };
  local protofields = {};
  --��ʼ��ȡfield type, abbr, name��ͬʱ�޸�name��ʹ������ʾ����������field
  for _, k in pairs( fs ) do
    local arg = fields[ k ];
    local func = arg[ 1 ] or "string";
    func = func:lower();
    func = ProtoFieldShort[ func ] or func; --��дת��

    local abbr = arg[ 2 ];
    local name = arg[ 3 ] or abbr;
    name = s2utf8( string.format( fmt, abbr, name ) );    --�����������
    
    local types = func;
    local exfunc;
    local f = rawget( ProtoField, types );
    if f then
      func = f;
    else
      exfunc = types;
      func = ProtoField.string;
      types = "string";
    end
    
    local field;
    if #arg > 3 then
      field = func( pre_fix .. abbr, name, select( 4, table.unpack( arg ) ) );
    else
      field = func( pre_fix .. abbr, name );
    end

    protofields[ abbr ] = field;
    protofieldsex[ abbr ] = { types = types,  field = field, exfunc = exfunc };
  end
  
  return protofieldsex, protofields;
end
