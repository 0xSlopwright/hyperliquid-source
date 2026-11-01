"""Independent pre-Rust three-case request relation from admitted37 native rows.
No production Rust, expected-file, register, opcode or captured-program execution.
"""

def observe(s):
    c, initial = s['codepoint'], s['initial_flag']
    assert 0 <= c <= 0x10ffff and not 0xd800 <= c <= 0xdfff
    flag, mode = initial, s['initial_mode']
    events = []
    if initial != 0:
        events.append({'kind':'bytes','hex':'20202020','flag_seen':initial,'mode_seen':mode})
        flag = initial if s['w_flag'] is None else s['w_flag']
        mode = mode if s['w_mode'] is None else s['w_mode']
        if s['w_status'] != 0:
            return {'path':'indent_error','status':1,'final_flag':flag,'final_mode':mode,'events':events}
    mode_input_flag = int(c == 10)
    events.append({'kind':'character','codepoint':c,'flag_seen':mode_input_flag,'mode_seen':mode})
    flag = mode_input_flag if s['c_flag'][mode] is None else s['c_flag'][mode]
    return {'path':'no_indent' if initial == 0 else 'indent_success','status':s['c_status'][mode],
            'final_flag':flag,'final_mode':mode,'events':events}
