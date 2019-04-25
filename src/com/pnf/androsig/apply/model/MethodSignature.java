/*
 * JEB Copyright PNF Software, Inc.
 * 
 *     https://www.pnfsoftware.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.pnf.androsig.apply.model;

import java.util.HashMap;
import java.util.Map;

import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.util.encoding.Conversion;

/**
 * Definition of one line of the signature files.
 * 
 * @author Ruoxiao Wang
 *
 */
public class MethodSignature {
    private String cname;
    private String mname;
    private String shorty;
    private String prototype;
    private int opcount;
    private String mhash_tight;
    private String mhash_loose;
    private String caller;
    private String versions;

    /**
     * Get the signature of the class.
     * 
     * @return the signature of the class
     */
    public String getCname() {
        return cname;
    }

    /**
     * Get the method name.
     * 
     * @return the name of the method
     */
    public String getMname() {
        return mname;
    }

    /**
     * Get the shorty of the method.
     * 
     * @return the shorty of the method
     */
    public String getShorty() {
        return shorty;
    }

    /**
     * Get the prototype of the method.
     * 
     * @return the prototype of the method
     */
    public String getPrototype() {
        return prototype;
    }

    /**
     * Get the number of instructions in the method.
     * 
     * @return the number of instructions in the method
     */
    public int getOpcount() {
        return opcount;
    }

    /**
     * Get the tight signature of the method.
     * 
     * @return the tight signature of the method
     */
    public String getMhash_tight() {
        return mhash_tight;
    }

    /**
     * Get the loose signature of the method.
     * 
     * @return the loose signature of the method
     */
    public String getMhash_loose() {
        return mhash_loose;
    }

    /**
     * Get the caller method list.
     * 
     * @return the list of all caller methods
     */
    public String getCaller() {
        return caller;
    }

    public Map<String, Integer> getTargetCaller() {
        return getTargetCaller(caller);
    }

    public static Map<String, Integer> getTargetCaller(String caller) {
        Map<String, Integer> targetCallerList = new HashMap<>();
        if(caller.isEmpty()) {
            return targetCallerList;
        }
        String[] targetCallers = caller.split("\\|");
        targetCallerList.clear();
        for(int i = 0; i < targetCallers.length; i++) {
            String[] tokens = targetCallers[i].split("=");
            targetCallerList.put(tokens[0], Integer.parseInt(tokens[1]));
        }
        return targetCallerList;
    }


    public String[] getVersions() {
        if(versions == null || versions.isEmpty()) {
            return null;
        }
        return versions.split(";");
    }

    public MethodSignature() {
    }

    public MethodSignature(String cname, String mname, String shorty, String prototype, String caller,
            String versions) {
        this.cname = cname;
        this.mname = mname;
        this.shorty = shorty;
        this.prototype = prototype;
        this.caller = caller;
        this.versions = versions;
    }

    /**
     * Get the information of one line in sig files.
     * 
     * @param one line in sig file
     * @return MethodLine Object (contains class path, method name, shorty, prototype, opcount,
     *         tight signature and loose signature)
     */
    public static MethodSignature parse(String line) {
        String[] tokens = line.trim().split(",");
        if(tokens.length < 8) {
            return null;
        }

        MethodSignature ml = new MethodSignature();
        ml.cname = tokens[0];
        if(!ml.cname.startsWith("L") || !ml.cname.endsWith(";")) {
            return null;
        }

        ml.mname = tokens[1];
        if(ml.mname.isEmpty()) {
            return null;
        }

        ml.shorty = tokens[2];
        if(ml.shorty.isEmpty()) {
            return null;
        }

        ml.prototype = tokens[3];
        if(ml.prototype.isEmpty()) {
            return null;
        }

        ml.opcount = Conversion.stringToInt(tokens[4]);
        if(ml.opcount < 0) {
            return null;
        }

        ml.mhash_tight = tokens[5].equals("null") ? "": tokens[5];

        ml.mhash_loose = tokens[6].equals("null") ? "": tokens[6];

        ml.caller = tokens[7].equals("null") ? "": tokens[7];

        // signature v2
        if(tokens.length > 8) {
            ml.versions = tokens[8];
        }
        return ml;
    }

    /**
     * Override toString
     */
    @Override
    public String toString() {
        return String.format("%s,%s,%s,%s,%d,%s,%s,%s", cname, mname, shorty, prototype, opcount, mhash_tight,
                mhash_loose, caller);
    }

    /* SET Of LAZY METHODS TO AVOID CREATION OF MethodSignature OBJECT */

    /**
     * Indicate if line contains signature data.
     * 
     * @return true if signature data is detected, false if line is blank or any comment
     */
    public static boolean isSignatureLine(String line) {
        return !line.isEmpty() && !line.startsWith(";");
    }

    public static String[] parseNative(String line) {
        String[] tokens = line.trim().split(",");
        if(tokens.length < 8) {
            return null;
        }
        return tokens;
    }

    /**
     * Get exact signature of method. See {@link SignatureHandler} for more details.
     * 
     * @return
     */
    public static String getTightSignature(String[] signatureLine) {
        return signatureLine[5];
    }

    /**
     * Get loose signature of method. See {@link SignatureHandler} for more details.
     * 
     * @return
     */
    public static String getLooseSignature(String[] signatureLine) {
        return signatureLine[6];
    }

    public static String getShorty(String[] signatureLine) {
        return signatureLine[2];
    }

    public static String getPrototype(String[] signatureLine) {
        return signatureLine[3];
    }

    public static String getClassname(String[] signatureLine) {
        return signatureLine[0];
    }

    public static String getMethodName(String[] signatureLine) {
        return signatureLine[1];
    }

    public static String[] getVersions(String[] signatureLine) {
        if(signatureLine.length <= 8 || signatureLine[8] == null) {
            return null;
        }
        return signatureLine[8].split(";");
    }

    // TODO remove all this (only for transition)
    public static String getTightSignature(MethodSignature signatureLine) {
        return signatureLine.mhash_tight;
    }

    public static String getLooseSignature(MethodSignature signatureLine) {
        return signatureLine.mhash_loose;
    }

    public static String getShorty(MethodSignature signatureLine) {
        return signatureLine.shorty;
    }

    public static String getPrototype(MethodSignature signatureLine) {
        return signatureLine.prototype;
    }

    public static String getClassname(MethodSignature signatureLine) {
        return signatureLine.cname;
    }

    public static String getMethodName(MethodSignature signatureLine) {
        return signatureLine.mname;
    }

    public static String[] getVersions(MethodSignature signatureLine) {
        return signatureLine.getVersions();
    }

    public String[] toTokens() {
        return new String[]{cname, mname, shorty, prototype, caller};
    }
}
