#if SWIGCSHARP

%rename("%(lowercamelcase)s") "";
%rename("%(camelcase)s", %$isfunction) "";
%rename("%(camelcase)s", %$isclass) "";
%rename("Telio") "telio";

%{
typedef void(*cs_telio_event_cb)(const char *);
void call_telio_event_cb(void *ctx, const char *msg) {
  cs_telio_event_cb cb = ctx;
  cb(msg);
}

typedef void(*cs_telio_logger_cb)(int, const char *);
void call_telio_logger_cb(void *ctx, int l, const char *msg) {
  cs_telio_logger_cb cb = ctx;
  cb(l, msg);
}
%}

%typemap(cscode) telio %{
  public delegate void EventDelegate(string message);
  public delegate void LoggerDelegate(TelioLogLevel level, string message);
%}

%typemap(cstype) telio_event_cb "EventDelegate";
%typemap(cstype) telio_logger_cb "LoggerDelegate";

%typemap(imtype) telio_event_cb "Telio.EventDelegate";
%typemap(imtype) telio_logger_cb "Telio.LoggerDelegate";

%typemap(ctype) telio_event_cb "cs_telio_event_cb";
%typemap(ctype) telio_logger_cb "cs_telio_logger_cb";

%typemap(csin) telio_event_cb "$csinput";
%typemap(csin) telio_logger_cb "$csinput";

%typemap(in) telio_event_cb %{
  $1 = (struct telio_event_cb) {
    .ctx = $input,
    .cb = call_telio_event_cb,
  };
%}
%typemap(in) telio_logger_cb %{
  $1 = (struct telio_logger_cb) {
    .ctx = $input,
    .cb = call_telio_logger_cb,
  };
%}

// dummy replacement to add exception checking in Telio.cs constructor
%exception telio %{$action%}

%extend telio {
    telio(const char* features, telio_event_cb events, enum telio_log_level level, telio_logger_cb logger) {
        telio *t;
        if (TELIO_RES_OK != telio_new(&t, features, events, level, logger)) {
            SWIG_CSharpSetPendingExceptionArgument(SWIG_CSharpArgumentException, "Failed to initiate telio", "features");
            return NULL;
        }
        return t;
    }
}

#endif