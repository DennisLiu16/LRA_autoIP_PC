import sys, os

def contains(mainstr, substr):
    return substr.lower() in mainstr.lower()

def log_ex(err):
  type, filename, ln = get_ex_info(err)
  print("type: ", type)
  print("file: ", filename)
  print("line: ", ln)

def get_ex_info(err):
  exception_type, exception_object, exception_traceback = sys.exc_info()
  filename = exception_traceback.tb_frame.f_code.co_filename
  line_number = exception_traceback.tb_lineno

  return exception_type, filename, line_number