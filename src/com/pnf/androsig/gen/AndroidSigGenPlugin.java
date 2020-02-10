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

package com.pnf.androsig.gen;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.pnf.androsig.common.AndroSigCommon;
import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.AbstractEnginesPlugin;
import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.IOptionDefinition;
import com.pnfsoftware.jeb.core.IPluginInformation;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.OptionDefinition;
import com.pnfsoftware.jeb.core.PluginInformation;
import com.pnfsoftware.jeb.core.Version;
import com.pnfsoftware.jeb.util.format.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Generate generic simple signatures for Android library methods. This plugin was ported from JEB1.
 * It is in no means intended to be used in professional systems: it is simply a POC show-casing how
 * easy it is to build a signing+matching system for DEX bytecode. It could easily be improved and
 * extended for all ICodeUnit in general, instead of being limited to IDexUnit.
 * <p>
 * This is the first part of a 2-part plugin. Second part: AndroidSigApplyPlugin.
 * <p>
 * ********************* Version 2 *********************
 * <p>
 * How to use:
 * <ul>
 * <li>Load a DEX file (UI, headless client, other)</li>
 * <li>Execute the plugin, optionally providing a filter regex and library name
 * </p>
 * <li>Signature file goes to <code>[JEB_PLUGINS]/android_sigs/[libname].sig</code></li> <li>To
 * apply sigs on unknown files, execute the AndroidSigApplyPlugin plugin</li> </ul>
 * 
 * @author Ruoxiao Wang
 */
public class AndroidSigGenPlugin extends AbstractEnginesPlugin {
    private static final ILogger logger = GlobalLog.getLogger(AndroidSigGenPlugin.class);

    @Override
    public IPluginInformation getPluginInformation() {
        return new PluginInformation("Android Code Signature Generator",
                "Generate generic signatures to identify Android libraries", "PNF Software",
                AndroSigCommon.VERSION, Version.create(3, 1, 0));
    }

    @Override
    public List<? extends IOptionDefinition> getExecutionOptionDefinitions() {
        return Arrays.asList(new OptionDefinition("libname", "Library name"),
                new OptionDefinition("filter", "Classname regular expression "));
    }

    @Override
    public void dispose() {
    }

    @Override
    public void load(IEnginesContext arg0) {
    }

    @Override
    public void execute(IEnginesContext context) {
        execute(context, null);
    }

    @Override
    public void execute(IEnginesContext engctx, Map<String, String> executionOptions) {
        IRuntimeProject prj = engctx.getProject(0);
        if(prj == null) {
            logger.info("There is no opened project");
            return;
        }

        File sigFolder;
        try {
            sigFolder = SignatureHandler.getSignaturesFolder(engctx);
        }
        catch(IOException ex) {
            throw new RuntimeException(ex);
        }

        String libname = executionOptions.get("libname");
        if(Strings.isBlank(libname)) {
            libname = prj.getName();
        }
        String filter = executionOptions.get("filter");
        if(!Strings.isBlank(filter)) {
            if(!filter.startsWith("L")) {
                logger.error("Classname Regular expression is invalid. Expected format: 'Landroid/support/v4/.*'");
                return;
            }
        }

        LibraryGenerator.generate(prj, sigFolder, libname, filter);
    }
}