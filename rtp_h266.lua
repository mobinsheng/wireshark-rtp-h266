-- Lua Dissector for rtp h266
-- Author: mobinsheng
--
-- 用法:
-- 1) 确保Wireshark自带了Lua - "About Wireshark" should say it is compiled with Lua
-- 2) 让Wireshark加载rtp_h266.lua插件，有两种方式：
--   2.1) 放到标准的目录plugins下，例如/path/Wireshark/plugins（MacOS下可能是/path/Wireshark/plugins/wireshark）, Wireshark会自动加载
--   2.2) 把插件放到任意目录，但是需要在init.lua文件的最后加上这句：dofile("/path/rtp_h266.lua")
-- 3) 打开"编辑-->首选项", 在 "Protocols" 下面, 选择H266，然后设置它的payload type，例如99
-- 4) 抓包
-- 5) 把UDP解析为RTP
-- 6) 使用"h266"或者"rtp.p_type == 99"进行过滤
--
--
------------------------------------------------------------------------------------------------
do
	-- 定义H266协议
    local H266 = Proto("h266", "h266")
	
	-- H266 nalu类型
	local H266_NALU_TYPE = {
		TRAIL = 0,
		STSA = 1,
		RADL = 2,
		RASL = 3,
		RSV_VCL_4 = 4,
		RSV_VCL_5 = 5,
		RSV_VCL_6 = 6,
		IDR_W_RADL = 7, -- 关键帧
		IDR_N_LP = 8,  -- 关键帧
		CRA = 9,
		GDR = 10,
		RSV_IRAP_11 = 11,
		OPI = 12,
		DCI = 13,
		VPS = 14,
		SPS = 15,
		PPS = 16,
		PREFIX_APS = 17,
		SUFFIX_APS = 18,
		PH = 19,
		AUD = 20,
		EOS = 21,
		EOB = 22,
		PREFIX_SEI = 23,
		SUFFIX_SEI = 24,
		FD = 25,
		RSV_NVCL_26 = 26,
		RSV_NVCL_27 = 27,
		AP = 28,
		FU = 29,
		--UNSPEC_28 = 28,
		--UNSPEC_29 = 29,
		UNSPEC_30 = 30,
		UNSPEC_31 = 31,
		INVALID = 32,
	}
	
    local prefs = H266.prefs
    prefs.dyn_pt = Pref.uint("rtp h266 dynamic payload type", 0, "The value > 95")
	
	-- nalu 头部长度
	local H266_NALU_HDR_SIZE = 2
	-- ap里面nalu size字段的长度
	local AP_NALU_SIZE_LEN = 2
	-- fu 头部长度
	local FU_HDR_SIZE = 1
	
	-- H266的字段map/字典
	local fields = H266.fields
	
	--[[
	ProtoField的用法：
	参数1：用于过滤时填入的信息
	参数2：展示到UI上的信息
	参数3：格式
	]]--
	-- Payload Header(Nalu Header) payload头部（和nalu头是一样，只不过type不一样）字段
	fields.payload_hdr_f = ProtoField.uint32("h266.payload.header.f", "f",base.DEC,nil)
	fields.payload_hdr_z = ProtoField.uint32("h266.payload.header.z", "z",base.DEC,nil) -- for 266
	fields.payload_hdr_type = ProtoField.uint32("h266.type", "type",base.DEC,nil)
	fields.payload_hdr_layer_id = ProtoField.uint32("h266.payload.header.layer_id", "layer_id",base.DEC,nil) -- for 265 266
	fields.payload_hdr_tid = ProtoField.uint32("h266.payload.header.tid", "tid",base.DEC,nil) -- for 265 266
	-- Payload Header(Nalu Header)
	-- ap: nalu header，AP包里的nalu头部字段
	fields.nalu_f = ProtoField.uint32("h266.nalu.f", "f",base.DEC,nil)
	fields.nalu_z = ProtoField.uint32("h266.nalu.z", "z",base.DEC,nil)
	fields.nalu_type = ProtoField.uint32("h266.type", "type",base.DEC,nil)
	fields.nalu_layer_id = ProtoField.uint32("h266.nalu.layer_id", "layer_id",base.DEC,nil) -- for 265 266
	fields.nalu_tid = ProtoField.uint32("h266.nalu.tid", "tid",base.DEC,nil) -- for 265 266
	-- ap: nalu header
	-- fu字段
	fields.fu_s = ProtoField.uint32("h266.fu.s", "fu.s",base.DEC,nil)
	fields.fu_e = ProtoField.uint32("h266.fu.e", "fu.e",base.DEC,nil)
	fields.fu_p = ProtoField.uint32("h266.fu.p", "fu.p",base.DEC,nil) -- for 266
	fields.fu_type = ProtoField.uint32("h266.type", "fu.type(real nalu type)",base.DEC,nil)
	
	-- 判断是否为vcl
	local function is_h266_vcl(nalu_type)
		if nalu_type == H266_NALU_TYPE.TRAIL then return true end
		if nalu_type == H266_NALU_TYPE.STSA then return true end
		if nalu_type == H266_NALU_TYPE.RADL then return true end
		if nalu_type == H266_NALU_TYPE.RASL then return true end
		if nalu_type == H266_NALU_TYPE.IDR_W_RADL then return true end
		if nalu_type == H266_NALU_TYPE.IDR_N_LP then return true end
		if nalu_type == H266_NALU_TYPE.CRA then return true end
		if nalu_type == H266_NALU_TYPE.GDR then return true end
		
		return false
	end
	
	-- 获取nalu的名字
	local function get_h266_nalu_name(nalu_type)
		local name = ""
		
		if nalu_type == -1 then
			name = "invalid" -- invalid
		elseif nalu_type == H266_NALU_TYPE.TRAIL then
			name = "DeltaFrame(TRAIL)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.STSA then
			name = "DeltaFrame(STSA)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.RADL then
			name = "DeltaFrame(RADL)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.RASL then
			name = "DeltaFrame(RASL)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.RSV_VCL_4 then
			name = "RSV_VCL_4" 
		elseif nalu_type == H266_NALU_TYPE.RSV_VCL_5 then
			name = "RSV_VCL_5" 
		elseif nalu_type == H266_NALU_TYPE.RSV_VCL_6 then
			name = "RSV_VCL_6" 
		elseif nalu_type == H266_NALU_TYPE.IDR_W_RADL then
			name = "KeyFrame(IDR_W_RADL)"
		elseif nalu_type == H266_NALU_TYPE.IDR_N_LP then
			name = "KeyFrame(IDR_N_LP)"
		elseif nalu_type == H266_NALU_TYPE.CRA then
			name = "DeltaFrame(CRA)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.GDR then
			name = "DeltaFrame(GDR)" -- vcl
		elseif nalu_type == H266_NALU_TYPE.RSV_IRAP_11 then
			name = "RSV_IRAP_11"
		elseif nalu_type == H266_NALU_TYPE.OPI then
			name = "OPI"
		elseif nalu_type == H266_NALU_TYPE.DCI then
			name = "DCI"
		elseif nalu_type == H266_NALU_TYPE.VPS then
			name = "VPS"
		elseif nalu_type == H266_NALU_TYPE.SPS then
			name = "SPS"
		elseif nalu_type == H266_NALU_TYPE.PPS then
			name = "PPS"
		elseif nalu_type == H266_NALU_TYPE.PREFIX_APS then
			name = "APS(PREFIX)"
		elseif nalu_type == H266_NALU_TYPE.SUFFIX_APS then
			name = "APS(SUFFIX)"
		elseif nalu_type == H266_NALU_TYPE.PH then
			name = "PH"
		elseif nalu_type == H266_NALU_TYPE.AUD then
			name = "AUD"
		elseif nalu_type == H266_NALU_TYPE.EOS then
			name = "EOS"
		elseif nalu_type == H266_NALU_TYPE.EOB then
			name = "EOB"
		elseif nalu_type == H266_NALU_TYPE.PREFIX_SEI then
			name = "SEI(PREFIX)"
		elseif nalu_type == H266_NALU_TYPE.SUFFIX_SEI then
			name = "SEI(SUFFIX)"
		elseif nalu_type == H266_NALU_TYPE.FD then
			name = "FD"
		elseif nalu_type == H266_NALU_TYPE.RSV_NVCL_26 then
			name = "RSV_NVCL_26"
		elseif nalu_type == H266_NALU_TYPE.RSV_NVCL_27 then
			name = "RSV_NVCL_27"
		elseif nalu_type == H266_NALU_TYPE.AP then
			name = "AP" -- 28
		elseif nalu_type == H266_NALU_TYPE.FU then
			name = "FU" -- 29
		elseif nalu_type == H266_NALU_TYPE.UNSPEC_30 then
			name = "UNSPEC_30"
		elseif nalu_type == H266_NALU_TYPE.UNSPEC_31 then
			name = "UNSPEC_31"
		else
			name = "other"
		end
		
		return name
	end
	
	-- 解析nalu/payload header
	local function parse_h266_nalu(buffer, offset)
		local nalu_header_first_byte = buffer(offset, 1):uint()
		local nalu_header_second_byte = buffer(offset + 1, 1):uint()
		
		nalu = {
			f = 0,
			z = 0,
			layer_id = 0,
			nalu_type = 0,
			tid = 0,
		}
		
		nalu.f = bit.rshift(bit.band(nalu_header_first_byte, 0x80), 7)
		nalu.z = bit.rshift(bit.band(nalu_header_first_byte, 0x40), 6)
		nalu.layer_id = bit.rshift(bit.band(nalu_header_first_byte, 0x3F), 0)
		
		nalu.nalu_type = bit.rshift(bit.band(nalu_header_second_byte, 0xF8), 3)
		nalu.tid = bit.rshift(bit.band(nalu_header_second_byte, 0x07), 0)
		
		return nalu
	end
	
	-- 解析FU
	local function parse_h266_fu(buffer, offset)
		local byte = buffer(offset, 1):uint()
		
		fu = {
			s = 0,
			e = 0,
			p = 0,
			fu_type = 0,
		}
		
		fu.s = bit.rshift(bit.band(byte, 0x80), 7)
		fu.e = bit.rshift(bit.band(byte, 0x40), 6)
		fu.p = bit.rshift(bit.band(byte, 0x20), 5)
		fu.fu_type = bit.rshift(bit.band(byte, 0x1F), 0)
		
		return fu
	end
	
	-- 解析rtp payload
	local function parse_rtp_payload(buffer, offset, subtree)
		local buf_len = buffer:len();
		
		-- 增加一个树状结构，展示payload header
		local payload_header_tree = subtree:add(H266, buffer(offset, H266_NALU_HDR_SIZE))
		
		-- 解析包头（payload hdr/nalu hdr）
		local packet_hdr = parse_h266_nalu(buffer, offset)
		
		-- nalu类型名字的字符串列表
		local nalu_type_name_list = ""
		
		if packet_hdr.nalu_type == H266_NALU_TYPE.AP then
			payload_header_tree:set_text("Payload Header(AP)")
		elseif packet_hdr.nalu_type == H266_NALU_TYPE.FU then
			payload_header_tree:set_text("Payload Header(Fu)")
		else
			payload_header_tree:set_text("NALU Header(Single Packet)")
		end
		
		payload_header_tree:add(fields.payload_hdr_f, buffer(offset, 1), packet_hdr.f)
		payload_header_tree:add(fields.payload_hdr_z, buffer(offset, 1), packet_hdr.z)
		payload_header_tree:add(fields.payload_hdr_layer_id, buffer(offset, 1), packet_hdr.layer_id)
		payload_header_tree:add(fields.payload_hdr_type, buffer(offset + 1, 1), packet_hdr.nalu_type)
		payload_header_tree:add(fields.payload_hdr_tid, buffer(offset + 1, 1), packet_hdr.tid)
		
		offset = offset + H266_NALU_HDR_SIZE
		
		-- 分片包（FU）
		if packet_hdr.nalu_type == H266_NALU_TYPE.FU then 
			-- Fu
			
			-- 增加一个树状结构，展示fu header
			fu_tree = subtree:add(H266, buffer(offset, buf_len - offset), "Fu")
			
			-- 解析fu 头部
			local fu = parse_h266_fu(buffer, offset)
			
			fu_tree:set_text("Fu")
			fu_tree:add(fields.fu_s, buffer(offset, 1), fu.s)
			fu_tree:add(fields.fu_e, buffer(offset, 1), fu.e)
			fu_tree:add(fields.fu_p, buffer(offset, 1), fu.p)
			fu_tree:add(fields.fu_type, buffer(offset, 1), fu.fu_type):append_text("(" .. get_h266_nalu_name(fu.fu_type) .. ")")
			
			offset = offset + FU_HDR_SIZE
			
			nalu_type_name_list = nalu_type_name_list .. " " .. get_h266_nalu_name(fu.fu_type)
			
			
		-- 聚合包（AP）
		elseif 	packet_hdr.nalu_type == H266_NALU_TYPE.AP then
			-- AP
			
			-- 增加一个树状结构，展示AP header
			local ap_header_tree = subtree:add(H266, buffer(offset, buf_len - offset))
			
			local nalu_size = buffer(offset, AP_NALU_SIZE_LEN):uint()
			
			offset = offset + AP_NALU_SIZE_LEN
			
			ap_header_tree:set_text("AP")
			
			while (buf_len - offset) > H266_NALU_HDR_SIZE do
				
				-- 解析ap里的nalu
				local nalu = parse_h266_nalu(buffer, offset)
				
				-- 增加一个树状结构，展示AP里面nalu header
				local nalu_header_tree = ap_header_tree:add(H266, buffer(offset, nalu_size))
				nalu_header_tree:set_text("NALU Header" .. "(" .. get_h266_nalu_name(nalu.nalu_type) .. ")")
				nalu_header_tree:add(fields.nalu_f, buffer(offset, 1), nalu.f)
				nalu_header_tree:add(fields.nalu_z, buffer(offset, 1), nalu.z)
				nalu_header_tree:add(fields.nalu_layer_id, buffer(offset, 1), nalu.layer_id)
				nalu_header_tree:add(fields.nalu_type, buffer(offset + 1, 1), nalu.nalu_type):append_text("(" .. get_h266_nalu_name(nalu.nalu_type) .. ")")
				nalu_header_tree:add(fields.nalu_tid, buffer(offset + 1, 1), nalu.tid)
				
				nalu_type_name_list = nalu_type_name_list .. " " .. get_h266_nalu_name(nalu.nalu_type)
				
				offset = offset + nalu_size
				
				if (buf_len - offset) > AP_NALU_SIZE_LEN then
					nalu_size = buffer(offset, AP_NALU_SIZE_LEN):uint()
					offset = offset + AP_NALU_SIZE_LEN
				else 
					break
				end
			end
			
		-- 单包（不分片也不聚合）
		else
			-- Single Packet
			-- 增加一个树状结构，展示
			single_packet_tree = subtree:add(H266, buffer(offset, buf_len - offset), "Single Packet")
			single_packet_tree:set_text("Single Packet" .. "(" .. get_h266_nalu_name(packet_hdr.nalu_type) .. ")")
			nalu_type_name_list = nalu_type_name_list .. " " .. get_h266_nalu_name(packet_hdr.nalu_type)
		end
		
		return offset, nalu_type_name_list
	end
	
	-- H266 过滤器
    function H266.dissector(tvb, pinfo, tree)
        local subtree = tree:add(H266, tvb(),"RTP Data(H266)")
		local offset, nalu_type_name_list = parse_rtp_payload(tvb, 0, subtree)
		
		-- 把nalu type信息展示到Info那一栏的最前面(如果不需要可以把下面三行注释掉)
		nalu_type_name_list = "[" .. nalu_type_name_list .. "]"
		local origin_info = tostring(pinfo.cols.info)
		pinfo.cols.info:set("[H266] " .. nalu_type_name_list .. " " .. origin_info)
		
		return true
    end
	
	
	-- 下面都是固定的写法，请不要修改!!!
    -- register dissector to dynamic payload type dissectorTable
	-- 注册H266过滤器到rtp动态payload类型中
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")
    dyn_payload_type_table:add("h266", H266)

    -- register dissector to RTP payload type
    local payload_type_table = DissectorTable.get("rtp.pt")
    local old_dissector = nil
    local old_dyn_pt = 0
    function H266.init()
        if (prefs.dyn_pt ~= old_dyn_pt) then
            if (old_dyn_pt > 0) then
                if (old_dissector == nil) then
                    payload_type_table:remove(old_dyn_pt, H266)
                else
                    payload_type_table:add(old_dyn_pt, old_dissector)
                end
            end
            old_dyn_pt = prefs.dyn_pt
            old_dissector = payload_type_table:get_dissector(old_dyn_pt)
            if (prefs.dyn_pt > 0) then
                payload_type_table:add(prefs.dyn_pt, H266)
            end
        end
    end

end
