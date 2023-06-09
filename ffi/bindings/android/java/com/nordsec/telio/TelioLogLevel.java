/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package com.nordsec.telio;

public final class TelioLogLevel {
  public final static TelioLogLevel LOG_CRITICAL = new TelioLogLevel("LOG_CRITICAL", libtelioJNI.LOG_CRITICAL_get());
  public final static TelioLogLevel LOG_ERROR = new TelioLogLevel("LOG_ERROR", libtelioJNI.LOG_ERROR_get());
  public final static TelioLogLevel LOG_WARNING = new TelioLogLevel("LOG_WARNING", libtelioJNI.LOG_WARNING_get());
  public final static TelioLogLevel LOG_INFO = new TelioLogLevel("LOG_INFO", libtelioJNI.LOG_INFO_get());
  public final static TelioLogLevel LOG_DEBUG = new TelioLogLevel("LOG_DEBUG", libtelioJNI.LOG_DEBUG_get());
  public final static TelioLogLevel LOG_TRACE = new TelioLogLevel("LOG_TRACE", libtelioJNI.LOG_TRACE_get());

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static TelioLogLevel swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + TelioLogLevel.class + " with value " + swigValue);
  }

  private TelioLogLevel(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private TelioLogLevel(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private TelioLogLevel(String swigName, TelioLogLevel swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static TelioLogLevel[] swigValues = { LOG_CRITICAL, LOG_ERROR, LOG_WARNING, LOG_INFO, LOG_DEBUG, LOG_TRACE };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

