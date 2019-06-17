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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.util.encoding.Conversion;
import com.pnfsoftware.jeb.util.format.Strings;

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
    private String versions;
    /** avoid split high cpu usage */
    private String[] versionsCache;
    private List<MethodSignatureRevision> revisions = new ArrayList<>();

    public static class MethodSignatureRevision {
        private int opcount;
        private String mhash_tight;
        private String mhash_loose;
        private String caller;
        private String versions;

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
         * Get the number of instructions in the method.
         * 
         * @return the number of instructions in the method
         */
        public int getOpcount() {
            return opcount;
        }

        /**
         * Get the caller method list.
         * 
         * @return the list of all caller methods
         */
        public String getCaller() {
            return caller;
        }

        public String[] getVersions() {
            if(versions == null || versions.isEmpty()) {
                return null;
            }
            return versions.split(";");
        }

        public String getTargetSuperType() {
            return MethodSignature.getTargetSuperType(caller);
        }

        public List<String> getTargetInterfaces() {
            return MethodSignature.getTargetInterfaces(caller);
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((caller == null) ? 0: caller.hashCode());
            result = prime * result + ((mhash_loose == null) ? 0: mhash_loose.hashCode());
            result = prime * result + ((mhash_tight == null) ? 0: mhash_tight.hashCode());
            result = prime * result + opcount;
            result = prime * result + ((versions == null) ? 0: versions.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if(this == obj)
                return true;
            if(obj == null)
                return false;
            if(getClass() != obj.getClass())
                return false;
            MethodSignatureRevision other = (MethodSignatureRevision)obj;
            if(caller == null) {
                if(other.caller != null)
                    return false;
            }
            else if(!caller.equals(other.caller))
                return false;
            if(mhash_loose == null) {
                if(other.mhash_loose != null)
                    return false;
            }
            else if(!mhash_loose.equals(other.mhash_loose))
                return false;
            if(mhash_tight == null) {
                if(other.mhash_tight != null)
                    return false;
            }
            else if(!mhash_tight.equals(other.mhash_tight))
                return false;
            if(opcount != other.opcount)
                return false;
            if(versions == null) {
                if(other.versions != null)
                    return false;
            }
            else if(!versions.equals(other.versions))
                return false;
            return true;
        }

    }

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

    public boolean isEmptyOp() {
        if(revisions.size() == 0) {
            return false;
        }
        for(MethodSignatureRevision rev: revisions) {
            if(rev.opcount != 0) {
                return false;
            }
        }
        return true;
    }

    public List<MethodSignatureRevision> getRevisions() {
        return revisions;
    }

    /**
     * Get the caller method list.
     * 
     * @return the list of all caller methods
     */
    public boolean hasCaller() {
        if(revisions.size() == 0) {
            return false;
        }
        if(revisions.size() != 1) {
            for(MethodSignatureRevision rev: revisions) {
                if(!Strings.isBlank(rev.caller)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @deprecated use {@link #getRevisions()} to retrieve the list of callers.
     * @return
     */
    @Deprecated
    public Map<String, Integer> getTargetCaller() {
        //return getTargetCaller(methodSignatureVersions.get(index).caller);
        return getTargetCaller(revisions.get(0).caller);
    }

    private String getParentField() {
        if(revisions.size() == 0) {
            return null;
        }
        String superT = revisions.get(0).caller;
        if(revisions.size() != 1) {
            for(MethodSignatureRevision rev: revisions) {
                if(!rev.caller.equals(superT)) {
                    return null;
                }
            }
        }
        if(superT.isEmpty()) {
            return null;
        }
        return superT;
    }

    /**
     * Retrieve the first metadata bound to this {@link MethodSignature} (stored in caller field).
     * For <parent> metadata, this return the super type.
     * 
     * @return
     */
    public String getTargetSuperType() {
        return getTargetSuperType(getParentField());
    }

    private static String getTargetSuperType(String superT) {
        if(superT == null) {
            return null;
        }
        String[] parents = superT.split("\\|\\|");
        if(parents.length == 0 || parents[0].isEmpty()) {
            return null;
        }
        List<String> parent = getParentClasses(parents[0]);
        if(parent == null || parent.size() != 1) {
            return null;
        }
        return parent.get(0);
    }

    /**
     * Retrieve the second metadata bound to this {@link MethodSignature} (stored in caller field).
     * For <parent> metadata, this return the implemented interfaces.
     * 
     * @return
     */
    public List<String> getTargetInterfaces() {
        return getTargetInterfaces(getParentField());
    }

    private static List<String> getTargetInterfaces(String superT) {
        if(superT == null) {
            return null;
        }
        String[] parents = superT.split("\\|\\|");
        if(parents.length != 2) {
            return null;
        }
        return getParentClasses(parents[1]);
    }

    private static List<String> getParentClasses(String parent) {
        List<String> targetCallerList = new ArrayList<>();
        if(parent.isEmpty()) {
            return targetCallerList;
        }
        String[] targetCallers = parent.split("\\|");
        targetCallerList.addAll(Arrays.asList(targetCallers));
        return targetCallerList;
    }

    public static Map<String, Integer> getTargetCaller(String caller) {
        Map<String, Integer> targetCallerList = new HashMap<>();
        if(caller.isEmpty()) {
            return targetCallerList;
        }
        String[] targetCallers = caller.split("\\|");
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
        if(versionsCache == null) {
            versionsCache = versions.split(";");
        }
        return versionsCache;
    }

    public MethodSignature() {
    }

    public MethodSignature(String cname, String mname, String shorty, String prototype,
            String versions) {
        this.cname = cname;
        this.mname = mname;
        this.shorty = shorty;
        this.prototype = prototype;
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
        return parse(line, true);
    }

    public static MethodSignature parse(String line, boolean strict) {
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
        if(strict && ml.shorty.isEmpty()) {
            return null;
        }

        ml.prototype = tokens[3];
        if(strict && ml.prototype.isEmpty()) {
            return null;
        }

        // signature v2
        ml.addRevision(buildRevision(tokens));
        if(tokens.length > 8) {
            ml.versions = tokens[8];
        }

        return ml;
    }

    public MethodSignatureRevision getOwnRevision() {
        return revisions.get(0);
    }

    private static MethodSignatureRevision buildRevision(String[] tokens) {
        MethodSignatureRevision revision = new MethodSignatureRevision();
        revision.opcount = Conversion.stringToInt(tokens[4]);
        if(revision.opcount < 0) {
            return null;
        }

        revision.mhash_tight = tokens[5].equals("null") ? "": tokens[5];

        revision.mhash_loose = tokens[6].equals("null") ? "": tokens[6];

        revision.caller = tokens[7].equals("null") ? "": tokens[7];

        // signature v2
        if(tokens.length > 8) {
            revision.versions = tokens[8];
        }
        return revision;
    }

    public void addRevision(MethodSignatureRevision revision) {
        if(revisions.contains(revision)) {
            return;
        }
        revisions.add(revision);

        if(versions == null) {
            versions = revision.versions;
        }
        else {
            versions += ";" + revision.versions;
        }
        versionsCache = null;
    }

    @Override
    public String toString() {
        return String.format("%s,%s,%s,%s", cname, mname, shorty, prototype);
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

    public static String[] parseNative(byte[] data, int startIndex, int endIndex) {
        String[] tokens = new String[9];
        int index = 0;
        int iStart = startIndex;
        for(int i = startIndex; i < endIndex; i++) {
            if(data[i] == ',') {
                if(index == 0 || index == 1 || index == 5 || index == 6) {
                    tokens[index] = new String(data, iStart, i - iStart);
                }
                index++;
                iStart = i + 1;
            }
        }
        index++;
        if(index < 8) {
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

    public String[] toTokens() {
        return new String[]{cname, mname, shorty, prototype};
    }

    public static boolean equalsClassMethodSig(MethodSignature ref, MethodSignature current) {
        return ref.getCname().equals(current.getCname()) && ref.getMname().equals(current.getMname())
                && ref.getPrototype().equals(current.getPrototype());
    }

    public static boolean equalsMethodSig(MethodSignature ref, MethodSignature current) {
        return ref.getMname().equals(current.getMname()) && ref.getPrototype().equals(current.getPrototype());
    }

}
