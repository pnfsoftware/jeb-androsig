/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.pnfsoftware.jeb.core.IOptionDefinition;
import com.pnfsoftware.jeb.core.OptionDefinition;
import com.pnfsoftware.jeb.util.format.Formatter;
import com.pnfsoftware.jeb.util.format.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * @author Cedric Lucas
 *
 */
public class DatabaseMatcherParameters {
    private static final ILogger logger = GlobalLog.getLogger(DatabaseMatcherParameters.class);

    // Parameters
    public int methodSizeBar = 6; // will skip method if its instruction size is no great than methodSizeBar
    public double matchedInstusPercentageBar = 0.5; // will skip the class if (total matched instructions / total instructions) is no greater than matchedMethodsPercentageBar
    public int standaloneConstructorMethodSizeBar = 20; // will skip class if only constructor is found with less than standaloneConstructorMethodSizeBar
    public boolean useCallerList = false;
    public boolean useReverseMatching = false;
    public int reverseMatchingClassThreshold = 10; // number of minimum class match required to enable reverse matching
    public double reverseMatchingFoundClassPercentage = 0.1; // will perform reverse matching only if (matched classes per file / total classes per file) is not greater than reverseMatchingFoundClassPercentage
    public int reverseMatchingMethodThreshold = 8; // minimum number of methods required to analyze a class
    public int reverseMatchingComplexObjectThreshold = 10; // minimum number of complex objects used in method signatures
    //public double reverseMatchingOpcountDeltaPercentage = 0.2; // delta allowed between two methods that do not have same hashcode

    public int matchedMethodsOneMatch = 10;

    public int complexSignatureParams = 2;

    public static DatabaseMatcherParameters parseParameters(Map<String, String> executionOptions) {
        DatabaseMatcherParameters params = new DatabaseMatcherParameters();
        params.methodSizeBar = parsePositiveInt(executionOptions, "methodSizeBar", 6);
        params.matchedMethodsOneMatch = parsePositiveInt(executionOptions, "matchedMethodsOneMatch", 10);
        params.complexSignatureParams = parsePositiveInt(executionOptions, "complexSignatureParams", 2);


        String matchedInstusPercentageBar = executionOptions.get("matchedInstusPercentageBar");
        if(!Strings.isBlank(matchedInstusPercentageBar)) {
            try {
                params.matchedInstusPercentageBar = Double.parseDouble(matchedInstusPercentageBar);
            }
            catch(NumberFormatException e) {
                logger.warn("Illegal matchedInstusPercentageBar parameter: \"%s\" (must be a double)",
                        Formatter.escapeString(matchedInstusPercentageBar));
            }
            if(params.matchedInstusPercentageBar < 0.0 || params.matchedInstusPercentageBar > 1.0) {
                params.matchedInstusPercentageBar = 0.5;
            }
        }
        return params;
    }

    private static int parsePositiveInt(Map<String, String> executionOptions, String paramName, int defaultValue) {
        String paramValue = executionOptions.get(paramName);
        int paramValueInt = defaultValue;
        if(!Strings.isBlank(paramValue)) {
            try {
                paramValueInt = Integer.parseInt(paramValue);
            }
            catch(NumberFormatException e) {
                logger.warn("Illegal %s parameter: \"%s\" (must be an integer)", paramName,
                        Formatter.escapeString(paramValue));
            }
            if(paramValueInt < 0) {
                paramValueInt = defaultValue;
            }
        }
        return paramValueInt;
    }

    public static List<? extends IOptionDefinition> getExecutionOptionDefinitions() {
        return Arrays.asList(new OptionDefinition(null,
                "Minimum number of instructions required to analyze a method by signature hashcode\n"
                        + "(methods with less than \"method size bar\" will be ignored by hashcode but can still be matched later).\n"
                        + "Value range: >= 0 (Default value: 6). The bigger will reduce false positive, the smaller will increase matching results"),
                new OptionDefinition("methodSizeBar", "Method size bar"),

                new OptionDefinition(null, "Minimum percentage of instructions to validate a class match\n"
                        + "(classes where (total matched instructions / total instructions) < \"matched instructions percentage bar\"\n"
                        + " will be ignored by hashcode detection, but can still be matched via context matching)\n"
                        + "Value range: 0.0 - 1.0 (Default value: 0.5). The bigger will reduce false positive, the smaller will increase matching results"),
                new OptionDefinition("matchedInstusPercentageBar", "Matched instructions percentage bar"),

                new OptionDefinition(null,
                        "Minimum number of found methods required to analyze a method when only one method matched by hashcode\n"
                                + "(this is a security mechanism for easy matching methods - when only one hashcode matches for a method -\n"
                                + " and the percentage bar is reached - in particular, the is easy when class is small)\n"
                                + "Value range: >= 0 (Default value: 10). The bigger will reduce false positive, the smaller will increase matching results"),
                new OptionDefinition("matchedMethodsOneMatch", "Minimum found methods on one match"),

                new OptionDefinition(null,
                        "Minimum number of java or android api parameters (or return value) used in a method signature to consider a method is complex\n"
                                + "(this is a security mechanism for easy matching methods: the expectation is to have at least\n"
                                + " \"Minimum number of complex parameters\" to consider that the matching is safe.\n"
                                + " This is to avoid percentage bar matching when only getter/setter matches for example)\n"
                                + "Value range: >= 0 (Default value: 2). The bigger will reduce false positive, the smaller will increase matching results"),
                new OptionDefinition("complexSignatureParams", "Minimum number of complex parameters"));
    }
}
