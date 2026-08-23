#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_pass_as3::AbcFile;
use disrobe_pass_as3::abc::{self, ClassInfo, MethodInfo, TraitInfo};
use disrobe_pass_as3::lifter::{LiftedBody, Stmt, lift_body};
use disrobe_pass_as3::swf::{self, Swf};

const TRAIT_KIND_METHOD: u8 = 1;
const TRAIT_KIND_GETTER: u8 = 2;
const TRAIT_KIND_SETTER: u8 = 3;

struct RemainderGroup {
    precondition: &'static str,
    must_stay_refused: bool,
    anonymous: usize,
    members: &'static [&'static str],
}

const MARKER_PRECEDENCE: &[&str] = &[
    "switch dispatch has an invalid target",
    "switch dispatch has a mid-region entry",
    "switch dispatch is backward or mixed",
    "switch dispatch region is irreducible",
    "forward dispatch mixes equality semantics",
    "forward dispatch selector or case has effects",
    "switch analysis budget exhausted",
    "unreconciled stack height",
    "unreconciled stack merge",
    "unreconciled scope height",
    "unreconciled scope values",
];

fn markers(stmts: &[Stmt], out: &mut BTreeSet<String>) {
    for statement in stmts {
        match statement {
            Stmt::Comment(text) => {
                out.insert(text.clone());
            }
            Stmt::IfBlock { body, .. }
            | Stmt::While { body, .. }
            | Stmt::DoWhile { body, .. }
            | Stmt::ForEach { body, .. }
            | Stmt::ForIn { body, .. }
            | Stmt::With { body, .. }
            | Stmt::For { body, .. } => markers(body, out),
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => {
                markers(then_body, out);
                markers(else_body, out);
            }
            Stmt::Try { body, catches } => {
                markers(body, out);
                for clause in catches {
                    markers(&clause.body, out);
                }
            }
            Stmt::StructuredSwitch { cases, .. } => {
                for case in cases {
                    markers(&case.body, out);
                }
            }
            _ => {}
        }
    }
}

fn residual_control_flow(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|statement: &Stmt| match statement {
        Stmt::Jump { .. } | Stmt::If { .. } | Stmt::Label(_) | Stmt::Switch { .. } => true,
        Stmt::IfBlock { body, .. }
        | Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::ForEach { body, .. }
        | Stmt::ForIn { body, .. }
        | Stmt::With { body, .. }
        | Stmt::For { body, .. } => residual_control_flow(body),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => residual_control_flow(then_body) || residual_control_flow(else_body),
        Stmt::Try { body, catches } => {
            residual_control_flow(body)
                || catches
                    .iter()
                    .any(|clause| residual_control_flow(&clause.body))
        }
        Stmt::StructuredSwitch { cases, .. } => {
            cases.iter().any(|case| residual_control_flow(&case.body))
        }
        _ => false,
    })
}

fn precondition(lifted: &LiftedBody) -> String {
    if !lifted.dropped_opcodes.is_empty() {
        return "unmodelled opcode".to_owned();
    }
    if !lifted.reached_terminator {
        return "no terminator reached".to_owned();
    }
    let mut found: BTreeSet<String> = BTreeSet::new();
    markers(&lifted.statements, &mut found);
    for candidate in MARKER_PRECEDENCE {
        if found.contains(*candidate) {
            return (*candidate).to_owned();
        }
    }
    if let Some(first) = found.iter().next() {
        return format!("other marker: {first}");
    }
    if residual_control_flow(&lifted.statements) {
        return "residual branch graph, no named reason".to_owned();
    }
    if lifted.opaque_operands > 0 {
        return "surviving merge operand".to_owned();
    }
    "unclassified".to_owned()
}

fn trait_key(abc_file: &AbcFile, info: &TraitInfo) -> Option<String> {
    let name: String = abc_file
        .cpool
        .render_multiname_property(info.name_index)
        .ok()?;
    match info.kind & 0x0F {
        TRAIT_KIND_METHOD => Some(name),
        TRAIT_KIND_GETTER => Some(format!("get {name}")),
        TRAIT_KIND_SETTER => Some(format!("set {name}")),
        _ => None,
    }
}

fn body_names(abc_file: &AbcFile) -> BTreeMap<u32, String> {
    let mut out: BTreeMap<u32, String> = BTreeMap::new();
    for (index, instance) in abc_file.instances.iter().enumerate() {
        let Ok(fqn): Result<String, _> = abc_file.cpool.render_multiname(instance.name_index)
        else {
            continue;
        };
        let simple: String = fqn.rsplit('.').next().unwrap_or(fqn.as_str()).to_owned();
        out.insert(instance.iinit, format!("{fqn}::{simple}"));
        let class_info: Option<&ClassInfo> = abc_file.classes.get(index);
        let instance_traits: std::slice::Iter<'_, TraitInfo> = instance.traits.iter();
        let static_traits: std::slice::Iter<'_, TraitInfo> =
            class_info.map_or_else(|| [].iter(), |info: &ClassInfo| info.traits.iter());
        for info in instance_traits.chain(static_traits) {
            if let Some(key) = trait_key(abc_file, info) {
                out.insert(info.method_index, format!("{fqn}::{key}"));
            }
        }
    }
    out
}

#[derive(Default)]
struct Census {
    bodies: usize,
    recovered: usize,
    named: BTreeMap<String, Vec<String>>,
    anonymous: BTreeMap<String, usize>,
}

fn take(census: &mut Census, abc_file: &AbcFile, label: &str) {
    let names: BTreeMap<u32, String> = body_names(abc_file);
    for body in &abc_file.method_bodies {
        let info: Option<&MethodInfo> = abc_file.methods.get(body.method as usize);
        let Ok(lifted): Result<LiftedBody, _> = lift_body(abc_file, body, info) else {
            continue;
        };
        census.bodies += 1;
        if lifted.structurally_recovered {
            census.recovered += 1;
            continue;
        }
        let group: String = precondition(&lifted);
        match names.get(&body.method) {
            Some(name) => census
                .named
                .entry(group)
                .or_default()
                .push(format!("{label}::{name}")),
            None => *census.anonymous.entry(group).or_default() += 1,
        }
    }
}

fn take_swf(census: &mut Census, bytes: &[u8], label: &str) {
    let Ok(parsed): Result<Swf, _> = swf::parse(bytes) else {
        return;
    };
    for blob in parsed.collect_do_abc() {
        let Ok(abc_file): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
            continue;
        };
        take(census, &abc_file, label);
    }
}

fn compare(census: &Census, pinned: &[RemainderGroup], population: &str) {
    let measured_groups: BTreeSet<&str> = census
        .named
        .keys()
        .map(String::as_str)
        .chain(census.anonymous.keys().map(String::as_str))
        .collect();
    let pinned_groups: BTreeSet<&str> = pinned
        .iter()
        .map(|group: &RemainderGroup| group.precondition)
        .collect();
    assert_eq!(
        measured_groups, pinned_groups,
        "{population}: the set of preconditions that stop recovery changed. A precondition that \
         appears without being pinned is an unexplained stop; one that disappears must be removed \
         here in the same commit that removes it from the lifter"
    );
    for group in pinned {
        let mut measured: Vec<String> = census
            .named
            .get(group.precondition)
            .cloned()
            .unwrap_or_default();
        measured.sort();
        let expected: Vec<String> = group
            .members
            .iter()
            .map(|name: &&str| (*name).to_owned())
            .collect();
        let gained: Vec<&String> = measured
            .iter()
            .filter(|name: &&String| !group.members.contains(&name.as_str()))
            .collect();
        let lost: Vec<&&str> = group
            .members
            .iter()
            .filter(|name: &&&str| !measured.iter().any(|m: &String| m == *name))
            .collect();
        assert_eq!(
            measured, expected,
            "{population}: the membership of `{}` changed. Newly stopped here: {gained:?}. No \
             longer stopped here: {lost:?}. Membership is pinned by name rather than by count so \
             that a body that regressed into this group cannot hide behind a body that left it",
            group.precondition
        );
        assert_eq!(
            census
                .anonymous
                .get(group.precondition)
                .copied()
                .unwrap_or(0),
            group.anonymous,
            "{population}: the count of bodies stopped by `{}` that no trait names changed. These \
             cannot be pinned by name because the ABC gives them none",
            group.precondition
        );
    }
}

const TRACKED_REMAINDER: &[RemainderGroup] = &[
    RemainderGroup {
        precondition: "residual branch graph, no named reason",
        must_stay_refused: false,
        anonymous: 0,
        members: &[
            "control_shapes::flash.Boot::start",
            "dispatch_shapes::flash.Boot::start",
            "json_tokenizer::flash.Boot::start",
            "opcode_breadth::OpcodeBreadth::loops",
            "opcode_breadth::flash.Boot::start",
            "switch_merge::flash.Boot::start",
            "whitespace_short_circuit::flash.Boot::start",
        ],
    },
    RemainderGroup {
        precondition: "unreconciled scope height",
        must_stay_refused: false,
        anonymous: 0,
        members: &[
            "control_shapes::flash.Boot::__string_rec",
            "dispatch_shapes::flash.Boot::__string_rec",
            "json_tokenizer::flash.Boot::__string_rec",
            "opcode_breadth::flash.Boot::__string_rec",
            "switch_merge::flash.Boot::__string_rec",
            "whitespace_short_circuit::flash.Boot::__string_rec",
        ],
    },
];

const CORPUS_REMAINDER: &[RemainderGroup] = &[
    RemainderGroup {
        precondition: "forward dispatch selector or case has effects",
        must_stay_refused: false,
        anonymous: 0,
        members: &[
            "10_More_Bullets::E::getBodyType",
            "10_More_Bullets::E::getEntityWithInfo",
            "10_More_Bullets::E::getEventWithInfo",
            "10_More_Bullets::E::getSceneByType",
            "10_More_Bullets::E::getStateWithInfo",
            "10_More_Bullets::bb.analytics.BBAnalytics::trackClickGetAndroid",
            "10_More_Bullets::bb.analytics.BBAnalytics::trackClickGetIpad",
            "10_More_Bullets::bb.analytics.BBAnalytics::trackClickGetIphone",
            "10_More_Bullets::bb.analytics.BBAnalytics::trackClickMoreGames",
            "10_More_Bullets::bb.analytics.BBAnalytics::trackEnterScene",
            "10_More_Bullets::bb.entity.state.sub.move.StateMoveLeft::onEnter",
            "10_More_Bullets::bb.entity.state.sub.move.StateMoveRight::onEnter",
            "10_More_Bullets::bb.level.BBLevel::onEntityDeath",
            "10_More_Bullets::bb.tween.BBTweenItem::finalStep",
            "10_More_Bullets::bb.tween.BBTweenItem::refresh",
            "10_More_Bullets::bb.tween.BBTweenItem::setup",
            "10_More_Bullets::bb.world.BBWorldFactory::addItem",
            "10_More_Bullets::logic.Collisions::doContact",
            "10_More_Bullets::logic.level.LevelEvents::heroVsLoot",
            "10_More_Bullets::logic.level.LevelManager::getOneLevel",
            "10_More_Bullets::nape.callbacks.InteractionListener::InteractionListener",
            "10_More_Bullets::nape.callbacks.InteractionListener::set interactionType",
            "10_More_Bullets::nape.callbacks.PreListener::PreListener",
            "10_More_Bullets::nape.callbacks.PreListener::set interactionType",
            "10_More_Bullets::nape.dynamics.Arbiter::toString",
            "10_More_Bullets::player.PlayerHelper::refreshTheStatsOnStartLevel",
            "10_More_Bullets::player.PlayerHelper::refreshTheStatsOnTick",
            "10_More_Bullets::zpp_nape.constraint.ZPP_Constraint::copyto",
            "10_More_Bullets::zpp_nape.geom.ZPP_Cutter::run",
            "10_More_Bullets::zpp_nape.geom.ZPP_Ray::circlesect2",
            "10_More_Bullets::zpp_nape.geom.ZPP_Simple::decompose",
            "10_More_Bullets::zpp_nape.geom.ZPP_Simple::isSimple",
            "10_More_Bullets::zpp_nape.geom.ZPP_Triangular::triangulate",
            "10_More_Bullets::zpp_nape.phys.ZPP_Compound::copy",
            "10_More_Bullets::zpp_nape.phys.ZPP_Interactor::setGroup",
            "10_More_Bullets::zpp_nape.space.ZPP_DynAABBPhase::broadphase",
            "10_More_Bullets::zpp_nape.space.ZPP_DynAABBPhase::sync_broadphase",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::convexCast",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::convexMultiCast",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::presteparb",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::step",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_Body::__fix_dbl_red",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSet::__fix_dbl_red",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSetPair::__fix_dbl_red",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionPair::__fix_dbl_red",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionVertex::__fix_dbl_red",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleEvent::__fix_dbl_red",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleSeg::__fix_dbl_red",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleVert::__fix_dbl_red",
            "ASmallCar::com.greensock.TweenMax::renderTime",
            "ASmallCar::com.junkbyte.console.core.Executer::execValue",
            "ASmallCar::com.junkbyte.console.view.PanelsManager::updateGraphs",
            "ASmallCar::mochi.as3.MochiServices::flush",
            "ASmallCar::mochi.as3.MochiServices::handleError",
            "ATV_Cross_Canada::_-4D._-p::_-BV",
            "ATV_Cross_Canada::_-98._-Q9::dynamic",
            "ATV_Cross_Canada::_-E3.TweenMax::renderTime",
            "ATV_Cross_Canada::_-O4._-HY::_-JN",
            "ATV_Cross_Canada::_-O4._-HY::flush",
            "BO_Awesome_Ranger::alternativa.engine3d.containers.ConflictContainer::drawAABBGeometry",
            "BO_Awesome_Ranger::alternativa.engine3d.containers.ConflictContainer::drawOOBBGeometry",
            "BO_Awesome_Ranger::alternativa.engine3d.core.View::getObjectsUnderPoint",
            "BO_Neo_Rider::build_fla.MainTimeline::objMove",
            "BO_Neo_Rider::mochi.as3.MochiServices::flush",
            "BO_Neo_Rider::mochi.as3.MochiServices::handleError",
            "BO_Neo_Rider::sandy.core.Renderer::render",
            "BO_Neo_Rider::sandy.core.interaction.VirtualMouse::interactWithTexture",
            "BO_Neo_Rider::sandy.materials.Material::dispose",
            "BO_Twin_Drivers_Level_9000::Game::isEnabledAddNewCar",
        ],
    },
    RemainderGroup {
        precondition: "no terminator reached",
        must_stay_refused: false,
        anonymous: 0,
        members: &[
            "10_More_Bullets::bb.panel.BBPanelPause::onTap",
            "10_More_Bullets::scene.SceneMenuPanel::onTap",
        ],
    },
    RemainderGroup {
        precondition: "residual branch graph, no named reason",
        must_stay_refused: false,
        anonymous: 0,
        members: &[
            "10_More_Bullets::com.google.analytics.data.X10::_clearInternal",
            "10_More_Bullets::com.hurlant.crypto.rsa.RSAKey::generate",
            "10_More_Bullets::com.hurlant.crypto.rsa.RSAKey::pkcs1unpad",
            "10_More_Bullets::com.hurlant.crypto.symmetric.AESKey::decrypt",
            "10_More_Bullets::com.hurlant.crypto.symmetric.CTRMode::core",
            "10_More_Bullets::com.hurlant.math.BigInteger::am",
            "10_More_Bullets::com.hurlant.math.BigInteger::compareTo",
            "10_More_Bullets::com.hurlant.math.BigInteger::exp",
            "10_More_Bullets::com.hurlant.math.BigInteger::fromArray",
            "10_More_Bullets::com.hurlant.math.BigInteger::multiplyTo",
            "10_More_Bullets::com.hurlant.math.BigInteger::multiplyUpperTo",
            "10_More_Bullets::com.hurlant.math.BigInteger::squareTo",
            "10_More_Bullets::com.hurlant.util.Base64::decodeToByteArray",
            "10_More_Bullets::flash.Boot::start",
            "10_More_Bullets::nape.dynamics.ArbiterList::at",
            "10_More_Bullets::nape.dynamics.ContactList::at",
            "10_More_Bullets::nape.dynamics.ContactList::clear",
            "10_More_Bullets::nape.geom.GeomPoly::area",
            "10_More_Bullets::nape.geom.GeomPoly::bottom",
            "10_More_Bullets::nape.geom.GeomPoly::bounds",
            "10_More_Bullets::nape.geom.GeomPoly::contains",
            "10_More_Bullets::nape.geom.GeomPoly::copy",
            "10_More_Bullets::nape.geom.GeomPoly::inflate",
            "10_More_Bullets::nape.geom.GeomPoly::isConvex",
            "10_More_Bullets::nape.geom.GeomPoly::left",
            "10_More_Bullets::nape.geom.GeomPoly::right",
            "10_More_Bullets::nape.geom.GeomPoly::size",
            "10_More_Bullets::nape.geom.GeomPoly::toString",
            "10_More_Bullets::nape.geom.GeomPoly::top",
            "10_More_Bullets::nape.geom.GeomPoly::transform",
            "10_More_Bullets::nape.geom.GeomPoly::winding",
            "10_More_Bullets::nape.phys.Body::contains",
            "10_More_Bullets::nape.phys.Body::crushFactor",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_BodyListener::addedToSpace",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_BodyListener::cbtype_change",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_CbSet::empty_intersection",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_CbSet::find_all",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_CbSet::single_intersection",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_ConstraintListener::addedToSpace",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_ConstraintListener::cbtype_change",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_InteractionListener::addedToSpace",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_InteractionListener::cbtype_change",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_InteractionListener::invalidate_precedence",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_OptionType::append",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_OptionType::append_type",
            "10_More_Bullets::zpp_nape.constraint.ZPP_Constraint::insert_cbtype",
            "10_More_Bullets::zpp_nape.dynamics.ZPP_SpaceArbiterList::at",
            "10_More_Bullets::zpp_nape.geom.ZPP_Collide::contactCollide",
            "10_More_Bullets::zpp_nape.geom.ZPP_Collide::containTest",
            "10_More_Bullets::zpp_nape.geom.ZPP_Collide::testCollide",
            "10_More_Bullets::zpp_nape.geom.ZPP_Convex::optimise",
            "10_More_Bullets::zpp_nape.geom.ZPP_Monotone::isMonotone",
            "10_More_Bullets::zpp_nape.geom.ZPP_PartitionedPoly::extract",
            "10_More_Bullets::zpp_nape.geom.ZPP_PartitionedPoly::extract_partitions",
            "10_More_Bullets::zpp_nape.geom.ZPP_PartitionedPoly::init",
            "10_More_Bullets::zpp_nape.geom.ZPP_PartitionedPoly::pull",
            "10_More_Bullets::zpp_nape.geom.ZPP_PartitionedPoly::pull_partitions",
            "10_More_Bullets::zpp_nape.geom.ZPP_PartitionedPoly::remove_collinear_vertices",
            "10_More_Bullets::zpp_nape.geom.ZPP_Ray::aabbsect",
            "10_More_Bullets::zpp_nape.geom.ZPP_Ray::polysect2",
            "10_More_Bullets::zpp_nape.geom.ZPP_Simple::clip_polygon",
            "10_More_Bullets::zpp_nape.geom.ZPP_Simplify::simplify",
            "10_More_Bullets::zpp_nape.geom.ZPP_SweepDistance::distance",
            "10_More_Bullets::zpp_nape.geom.ZPP_SweepDistance::distanceBody",
            "10_More_Bullets::zpp_nape.geom.ZPP_Triangular::optimise",
            "10_More_Bullets::zpp_nape.phys.ZPP_Body::removedFromSpace",
            "10_More_Bullets::zpp_nape.phys.ZPP_Interactor::insert_cbtype",
            "10_More_Bullets::zpp_nape.shape.ZPP_Polygon::cleanup_lvert",
            "10_More_Bullets::zpp_nape.shape.ZPP_Polygon::lverts_post_adder",
            "10_More_Bullets::zpp_nape.shape.ZPP_Polygon::splice_collinear_real",
            "10_More_Bullets::zpp_nape.shape.ZPP_Polygon::valid",
            "10_More_Bullets::zpp_nape.space.ZPP_AABBTree::insertLeaf",
            "10_More_Bullets::zpp_nape.space.ZPP_DynAABBPhase::__remove",
            "10_More_Bullets::zpp_nape.space.ZPP_DynAABBPhase::clear",
            "10_More_Bullets::zpp_nape.space.ZPP_DynAABBPhase::rayCast",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::clear",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::removed_shape",
            "10_More_Bullets::zpp_nape.space.ZPP_SweepPhase::broadphase",
            "10_More_Bullets::zpp_nape.util.FastHash2_Hashable2_Boolfalse::has",
            "10_More_Bullets::zpp_nape.util.FastHash2_Hashable2_Boolfalse::remove",
            "10_More_Bullets::zpp_nape.util.ZPP_BitmapDebug::__line",
            "10_More_Bullets::zpp_nape.util.ZPP_MixVec2List::at",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_Body::insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_Body::try_insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_Body::try_insert_bool",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSet::insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSet::try_insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSet::try_insert_bool",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSetPair::insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSetPair::try_insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSetPair::try_insert_bool",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionPair::insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionPair::try_insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionPair::try_insert_bool",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionVertex::insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionVertex::try_insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionVertex::try_insert_bool",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleEvent::insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleEvent::try_insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleEvent::try_insert_bool",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleSeg::insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleSeg::try_insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleSeg::try_insert_bool",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleVert::insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleVert::try_insert",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleVert::try_insert_bool",
            "1942_Battles_In_The_Sky::ProgBar::create",
            "1942_Battles_In_The_Sky::ProgBar::updatePercent",
            "1942_Battles_In_The_Sky::ProgBar::updateValue",
            "1942_Battles_In_The_Sky::gs.TweenLite::set enabled",
            "1942_Battles_In_The_Sky::gs.plugins.FilterPlugin::onCompleteTween",
            "1942_Battles_In_The_Sky::mx.utils.NameUtil::displayObjectToString",
            "1942_Battles_In_The_Sky::org.flixel.FlxG::addBitmap",
            "1942_Battles_In_The_Sky::org.flixel.FlxG::addBitmap_data",
            "1942_Battles_In_The_Sky::org.flixel.FlxG::createBitmap",
            "1942_Battles_In_The_Sky::org.flixel.FlxTilemap::overlaps",
            "ASmallCar::com.greensock.OverwriteManager::manageOverwrites",
            "ASmallCar::com.greensock.TweenLite::init",
            "ASmallCar::com.greensock.TweenMax::changePause",
            "ASmallCar::com.greensock.TweenMax::getAllTweens",
            "ASmallCar::com.greensock.TweenMax::getTweensOf",
            "ASmallCar::com.greensock.TweenMax::init",
            "ASmallCar::com.greensock.TweenMax::insertPropTween",
            "ASmallCar::com.greensock.TweenMax::isTweening",
            "ASmallCar::com.greensock.TweenMax::killAll",
            "ASmallCar::com.greensock.TweenMax::killChildTweensOf",
            "ASmallCar::com.greensock.TweenMax::killProperties",
            "ASmallCar::com.greensock.plugins.BezierPlugin::set changeFactor",
            "ASmallCar::com.greensock.plugins.EndArrayPlugin::init",
            "ASmallCar::com.greensock.plugins.EndArrayPlugin::set changeFactor",
            "ASmallCar::com.greensock.plugins.FilterPlugin::initFilter",
            "ASmallCar::com.greensock.plugins.FilterPlugin::onCompleteTween",
            "ASmallCar::com.greensock.plugins.FilterPlugin::set changeFactor",
            "ASmallCar::com.greensock.plugins.FrameLabelPlugin::onInitTween",
            "ASmallCar::com.greensock.plugins.TintPlugin::init",
            "ASmallCar::com.greensock.plugins.TweenPlugin::activate",
            "ASmallCar::com.greensock.plugins.TweenPlugin::killProps",
            "ASmallCar::com.greensock.plugins.TweenPlugin::onTweenEvent",
            "ASmallCar::com.greensock.plugins.TweenPlugin::updateTweens",
            "ASmallCar::com.junkbyte.console.Console::listenUncaughtErrors",
            "ASmallCar::com.junkbyte.console.core.CommandLine::run",
            "ASmallCar::com.junkbyte.console.core.Executer::execNest",
            "ASmallCar::com.junkbyte.console.core.MemoryMonitor::Gc",
            "ASmallCar::com.junkbyte.console.core.Remoting::remoteSync",
            "ASmallCar::com.junkbyte.console.core.Remoting::set remoting",
            "ASmallCar::com.junkbyte.console.view.AbstractPanel::onTextFieldMouseMove",
            "ASmallCar::flare.core.Canvas3D::_140",
            "ASmallCar::flare.core.Canvas3D::setup",
            "ASmallCar::flare.loaders.Flare3DLoader::_137",
            "ASmallCar::mochi.as3.MochiServices::bringToTop",
            "ASmallCar::mx.utils.NameUtil::displayObjectToString",
            "ASmallCar::spill.localisation.TextFieldFit::updateProperties",
            "ATV_Cross_Canada::Playtomic._-6v::Base64Decode",
            "ATV_Cross_Canada::_-98._-3A::simplify",
            "ATV_Cross_Canada::_-E3.TweenMax::_-9U",
            "ATV_Cross_Canada::_-E3.TweenMax::_-BQ",
            "ATV_Cross_Canada::_-E3.TweenMax::_-FP",
            "ATV_Cross_Canada::_-E3.TweenMax::_-Oq",
            "ATV_Cross_Canada::_-E3.TweenMax::_-b",
            "ATV_Cross_Canada::_-E3._-Jr::init",
            "ATV_Cross_Canada::_-E3._-OQ::manageOverwrites",
            "ATV_Cross_Canada::_-Fw.EndArrayPlugin::init",
            "ATV_Cross_Canada::_-Fw.EndArrayPlugin::set changeFactor",
            "ATV_Cross_Canada::_-Fw._-6d::_-N3",
            "ATV_Cross_Canada::_-Fw._-Fn::_-H7",
            "ATV_Cross_Canada::_-Fw._-Fn::_-R2",
            "ATV_Cross_Canada::_-Fw._-L0::_-AS",
            "ATV_Cross_Canada::_-Fw._-L0::_-Ih",
            "ATV_Cross_Canada::_-Fw._-L0::set changeFactor",
            "ATV_Cross_Canada::_-Fw._-Le::set changeFactor",
            "ATV_Cross_Canada::_-Fw._-Nj::set changeFactor",
            "ATV_Cross_Canada::_-Fw._-PE::set changeFactor",
            "ATV_Cross_Canada::_-Fw._-Qo::onInitTween",
            "ATV_Cross_Canada::_-I1._-48::removeObject",
            "ATV_Cross_Canada::_-J1.Level::_-Qq",
            "ATV_Cross_Canada::_-J1._-3e::init",
            "ATV_Cross_Canada::_-JM._-I-::_-0a",
            "ATV_Cross_Canada::_-JM._-I-::clear",
            "ATV_Cross_Canada::_-Qp._-6X::_-RL",
            "ATV_Cross_Canada::_-Qp._-Lm::_-RL",
            "ATV_Cross_Canada::_-Qp._-OG::poly2poly_test",
            "ATV_Cross_Canada::_-Qp._-Qc::_-RL",
            "ATV_Cross_Canada::_-RG.Base64::_-8r",
            "BO_Awesome_Ranger::TweenEngine::_-d",
            "BO_Awesome_Ranger::TweenEngine::addTween",
            "BO_Awesome_Ranger::TweenEngine::update",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3D::cullingInCamera",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::_-4b",
            "BO_Awesome_Ranger::alternativa.engine3d.core.View::_-3G",
            "BO_Awesome_Ranger::alternativa.engine3d.core.View::_-3f",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-x",
            "BO_Awesome_Ranger::alternativa.engine3d.materials.TextureMaterial::calculateMipMaps",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::checkIntersection",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::intersectRay",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::optimizeForDynamicBSP",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Sprite3D::intersectRay",
            "BO_Awesome_Ranger::bodies.BossScene::_-0r",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.GameAllianzApi::cache",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.gui.Background::_-5",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.gui.Background::_-6b",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.utils.Base64::decodeToByteArray",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.utils.FireBugConsole::_-67",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.utils.GlobalTrace::iniFromFlashVars",
            "BO_Neo_Rider::ZumspielAPI::_encode_",
            "BO_Neo_Rider::mochi.as3.MochiServices::bringToTop",
            "BO_Neo_Rider::sandy.core.data.BSPNode::lazyBSPFaces2Planes",
            "BO_Neo_Rider::sandy.materials.ColorMaterial::renderPolygon",
            "BO_Neo_Rider::sandy.materials.attributes.LineAttributes::draw",
            "BO_Neo_Rider::sandy.view.Frustum::boxInFrustum",
            "BO_Twin_Drivers_Level_9000::Game::updateWagons",
            "BO_Twin_Drivers_Level_9000::Preloader::cleanRow",
            "BO_Twin_Drivers_Level_9000::Preloader::newsCallback",
            "BO_Twin_Drivers_Level_9000::com.adobe.serialization.json.JSONDecoder::parseArray",
            "BO_Twin_Drivers_Level_9000::com.adobe.serialization.json.JSONDecoder::parseObject",
            "BO_Twin_Drivers_Level_9000::com.adobe.serialization.json.JSONTokenizer::skipIgnored",
            "BO_Twin_Drivers_Level_9000::lib.GCookie::erase",
            "BO_Twin_Drivers_Level_9000::lib.GCookie::set",
        ],
    },
    RemainderGroup {
        precondition: "surviving merge operand",
        must_stay_refused: false,
        anonymous: 29,
        members: &[
            "10_More_Bullets::zpp_nape.callbacks.ZPP_CbSet::compatible",
            "10_More_Bullets::zpp_nape.callbacks.ZPP_CbSetPair::__validate",
            "10_More_Bullets::zpp_nape.phys.ZPP_Interactor::int_callback",
            "ATV_Cross_Canada::Playtomic._-P8::_-7z",
            "ATV_Cross_Canada::Playtomic._-P8::_-Ft",
            "ATV_Cross_Canada::_-E3.TweenMax::TweenMax",
            "ATV_Cross_Canada::_-Fw._-4::onInitTween",
            "ATV_Cross_Canada::_-Fw._-Pt::onInitTween",
            "ATV_Cross_Canada::_-J1._-4h::keyDown",
            "ATV_Cross_Canada::_-J1._-4h::keyUp",
            "ATV_Cross_Canada::_-Nh._-7W::update",
            "ATV_Cross_Canada::_-P._-IL::_-Gl",
            "ATV_Cross_Canada::engine.comp.CompPoint2::CompPoint2",
            "BO_Awesome_Ranger::Equations::easeOutElastic",
            "BO_Awesome_Ranger::Input::_-35",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-08",
            "BO_Awesome_Ranger::bodies.Sign::updatePosition",
            "BO_Neo_Rider::Retry::frame1",
            "BO_Neo_Rider::ZumspielAPI::_send_",
            "BO_Neo_Rider::build_fla.MainTimeline::citySet",
            "BO_Neo_Rider::build_fla.MainTimeline::frame1",
            "BO_Neo_Rider::build_fla.MainTimeline::frame10",
            "BO_Neo_Rider::build_fla.MainTimeline::frame15",
            "BO_Neo_Rider::build_fla.MainTimeline::objPieces",
            "BO_Neo_Rider::com.zumspiel.ZAPI::addToStage",
            "BO_Neo_Rider::mochi.as3.MochiAd::_parseOptions",
            "BO_Neo_Rider::mochi.as3.MochiAd::adShowing",
            "BO_Neo_Rider::mochi.as3.MochiAd::createEmptyMovieClip",
            "BO_Neo_Rider::mochi.as3.MochiAd::showClickAwayAd",
            "BO_Neo_Rider::mochi.as3.MochiAd::showInterLevelAd",
            "BO_Neo_Rider::mochi.as3.MochiAd::showPreGameAd",
            "BO_Neo_Rider::mochi.as3.MochiAd::unload",
            "BO_Neo_Rider::mochi.as3.MochiEventDispatcher::removeEventListener",
            "BO_Neo_Rider::mochi.as3.MochiEvents::setNotifications",
            "BO_Neo_Rider::mochi.as3.MochiEvents::trigger",
            "BO_Neo_Rider::mochi.as3.MochiInventory::getConsumableBag",
            "BO_Neo_Rider::mochi.as3.MochiInventory::newItems",
            "BO_Neo_Rider::mochi.as3.MochiInventory::setProperty",
            "BO_Neo_Rider::mochi.as3.MochiInventory::sync",
            "BO_Neo_Rider::mochi.as3.MochiServices::addLinkEvent",
            "BO_Neo_Rider::mochi.as3.MochiServices::clickMovie",
            "BO_Neo_Rider::mochi.as3.MochiServices::connect",
            "BO_Neo_Rider::mochi.as3.MochiServices::connectWait",
            "BO_Neo_Rider::mochi.as3.MochiServices::init",
            "BO_Neo_Rider::mochi.as3.MochiServices::initComChannels",
            "BO_Neo_Rider::mochi.as3.MochiServices::loadCommunicator",
            "BO_Neo_Rider::mochi.as3.MochiServices::send",
            "BO_Neo_Rider::mochi.as3.MochiServices::setContainer",
            "BO_Neo_Rider::mochi.as3.MochiServices::urlOptions",
            "BO_Neo_Rider::mochi.as3.MochiSync::setProperty",
            "BO_Neo_Rider::mochi.as3.MochiUserData::deserialize",
            "BO_Neo_Rider::mochi.as3.MochiUserData::request",
            "BO_Neo_Rider::mochi.as3.MochiUserData::serialize",
            "BO_Neo_Rider::sandy.bounds.BBox::addInternalPoint",
            "BO_Neo_Rider::sandy.bounds.BBox::addInternalPointXYZ",
            "BO_Neo_Rider::sandy.bounds.BBox::clone",
            "BO_Neo_Rider::sandy.bounds.BBox::copy",
            "BO_Neo_Rider::sandy.bounds.BBox::getEdges",
            "BO_Neo_Rider::sandy.bounds.BSphere::copy",
            "BO_Neo_Rider::sandy.core.Scene3D::render",
            "BO_Neo_Rider::sandy.core.Scene3D::set root",
            "BO_Neo_Rider::sandy.core.data.BSPNode::makeLazyBSP",
            "BO_Neo_Rider::sandy.core.data.Matrix4::deserialize",
            "BO_Neo_Rider::sandy.core.data.Matrix4::transform",
            "BO_Neo_Rider::sandy.core.data.Matrix4::transform3x3",
            "BO_Neo_Rider::sandy.core.data.Point3D::deserialize",
            "BO_Neo_Rider::sandy.core.data.Polygon::__update",
            "BO_Neo_Rider::sandy.core.data.Polygon::_onInteraction",
            "BO_Neo_Rider::sandy.core.data.Pool::Pool",
            "BO_Neo_Rider::sandy.core.data.PrimitiveFace::set appearance",
            "BO_Neo_Rider::sandy.core.data.Vertex::clone",
            "BO_Neo_Rider::sandy.core.data.Vertex::getCameraPoint3D",
            "BO_Neo_Rider::sandy.core.data.Vertex::getPoint3D",
            "BO_Neo_Rider::sandy.core.interaction.TextLink::_init",
            "BO_Neo_Rider::sandy.core.interaction.TextLink::getTextLinks",
            "BO_Neo_Rider::sandy.core.light.Light3D::setDirection",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::lookAt",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::moveForward",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::moveHorizontally",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::moveSideways",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::moveUpwards",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::set matrix",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::setPosition",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::translate",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::update",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::updateTransform",
            "BO_Neo_Rider::sandy.core.scenegraph.Camera3D::Camera3D",
            "BO_Neo_Rider::sandy.core.scenegraph.Camera3D::projectArray",
            "BO_Neo_Rider::sandy.core.scenegraph.Camera3D::projectVertex",
            "BO_Neo_Rider::sandy.core.scenegraph.Camera3D::setPerspectiveProjection",
            "BO_Neo_Rider::sandy.core.scenegraph.Camera3D::update",
            "BO_Neo_Rider::sandy.core.scenegraph.Geometry3D::clone",
            "BO_Neo_Rider::sandy.core.scenegraph.Geometry3D::generateVertexNormals",
            "BO_Neo_Rider::sandy.core.scenegraph.Geometry3D::setFaceNormal",
            "BO_Neo_Rider::sandy.core.scenegraph.Geometry3D::setFaceUVCoordsIds",
            "BO_Neo_Rider::sandy.core.scenegraph.Geometry3D::setFaceVertexIds",
            "BO_Neo_Rider::sandy.core.scenegraph.Geometry3D::setUVCoords",
            "BO_Neo_Rider::sandy.core.scenegraph.Geometry3D::setVertex",
            "BO_Neo_Rider::sandy.core.scenegraph.Geometry3D::setVertexNormal",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::addChild",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::removeChild",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::set appearance",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::set enableBackFaceCulling",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::set enableClipping",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::set enableEvents",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::set enableInteractivity",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::set scene",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::set useSingleContainer",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::set visible",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::update",
            "BO_Neo_Rider::sandy.core.scenegraph.Shape3D::Shape3D",
            "BO_Neo_Rider::sandy.core.scenegraph.Shape3D::__destroyPolygons",
            "BO_Neo_Rider::sandy.core.scenegraph.Shape3D::__generatePolygons",
            "BO_Neo_Rider::sandy.core.scenegraph.Shape3D::_onInteraction",
            "BO_Neo_Rider::sandy.core.scenegraph.Shape3D::set appearance",
            "BO_Neo_Rider::sandy.core.scenegraph.Shape3D::set enableEvents",
            "BO_Neo_Rider::sandy.core.scenegraph.Shape3D::set enableInteractivity",
            "BO_Neo_Rider::sandy.core.scenegraph.Shape3D::set geometryCenter",
            "BO_Neo_Rider::sandy.core.scenegraph.Shape3D::set scene",
            "BO_Neo_Rider::sandy.core.scenegraph.Sound3D::soundCompleteHandler",
            "BO_Neo_Rider::sandy.core.scenegraph.Sound3D::updateChannelRef",
            "BO_Neo_Rider::sandy.core.scenegraph.Sound3D::updateSoundTransform",
            "BO_Neo_Rider::sandy.core.scenegraph.Sprite2D::display",
            "BO_Neo_Rider::sandy.core.scenegraph.Sprite2D::set content",
            "BO_Neo_Rider::sandy.core.scenegraph.TransformGroup::updateBoundingVolumes",
            "BO_Neo_Rider::sandy.materials.Appearance::dispose",
            "BO_Neo_Rider::sandy.materials.BitmapMaterial::renderRec",
            "BO_Neo_Rider::sandy.materials.BitmapMaterial::renderTriangle",
            "BO_Neo_Rider::sandy.materials.BitmapMaterial::set texture",
            "BO_Neo_Rider::sandy.materials.BitmapMaterial::setTiling",
            "BO_Neo_Rider::sandy.materials.BitmapMaterial::setTransparency",
            "BO_Neo_Rider::sandy.materials.Material::init",
            "BO_Neo_Rider::sandy.math.FastMath::initialize",
            "BO_Neo_Rider::sandy.math.PlaneMath::createFromNormalAndPoint",
            "BO_Neo_Rider::sandy.math.PlaneMath::normalizePlane",
            "BO_Neo_Rider::sandy.math.Point3DMath::normalize",
            "BO_Neo_Rider::sandy.primitive.Box::_generateFaces",
            "BO_Neo_Rider::sandy.view.Frustum::Frustum",
            "BO_Neo_Rider::sandy.view.Frustum::clipLineFrontPlane",
            "BO_Neo_Rider::sandy.view.Frustum::clipPolygon",
            "BO_Neo_Rider::sandy.view.Frustum::computePlanes",
        ],
    },
    RemainderGroup {
        precondition: "switch dispatch is backward or mixed",
        must_stay_refused: true,
        anonymous: 1,
        members: &[
            "10_More_Bullets::bb.leaderboard.scoreDB.BBScoreDB::onData",
            "10_More_Bullets::bb.manager.BBInput::getLetterFromCode",
            "10_More_Bullets::bb.panel.BBPanelClavier::onTapLetter",
            "10_More_Bullets::com.google.analytics.GATracker::_factory",
            "10_More_Bullets::com.google.analytics.campaign.CampaignManager::getOrganicCampaign",
            "10_More_Bullets::com.google.analytics.campaign.CampaignManager::hasNoOverride",
            "10_More_Bullets::com.google.analytics.core.Buffer::_onFlushStatus",
            "10_More_Bullets::com.google.analytics.core.Buffer::save",
            "10_More_Bullets::com.google.analytics.core.GIFRequest::_debugSend",
            "10_More_Bullets::com.google.analytics.debug.Background::drawRounded",
            "10_More_Bullets::com.google.analytics.debug.Debug::onKey",
            "10_More_Bullets::com.google.analytics.debug.DebugConfiguration::set mode",
            "10_More_Bullets::com.google.analytics.debug.Info::onLink",
            "10_More_Bullets::com.google.analytics.debug.Layout::onKey",
            "10_More_Bullets::com.google.analytics.debug.UISprite::alignTo",
            "10_More_Bullets::com.google.analytics.debug.Warning::onLink",
            "10_More_Bullets::com.google.analytics.utils.Environment::_findProtocol",
            "10_More_Bullets::com.google.analytics.utils.Environment::get screenColorDepth",
            "10_More_Bullets::com.google.analytics.utils.URL::get domain",
            "10_More_Bullets::com.google.analytics.utils.URL::get protocol",
            "10_More_Bullets::com.google.analytics.utils.Version::toString",
            "10_More_Bullets::com.google.analytics.v4.Bridge::trackEvent",
            "10_More_Bullets::com.google.analytics.v4.Tracker::trackEvent",
            "10_More_Bullets::com.hurlant.crypto.Crypto::getCipher",
            "10_More_Bullets::com.hurlant.crypto.Crypto::getHash",
            "10_More_Bullets::com.hurlant.crypto.Crypto::getKeySize",
            "10_More_Bullets::com.hurlant.crypto.Crypto::getMode",
            "10_More_Bullets::com.hurlant.crypto.Crypto::getPad",
            "10_More_Bullets::com.hurlant.math.BigInteger::toString",
            "1942_Battles_In_The_Sky::ProgBar::ProgBar",
            "1942_Battles_In_The_Sky::com.levels.base_level.Level::generate_level_items",
            "1942_Battles_In_The_Sky::org.flixel.FlxGame::onKeyUp",
            "ASmallCar::SfxrParams::pow",
            "ASmallCar::SfxrSynth::synthWave",
            "ASmallCar::com.junkbyte.console.core.Executer::operate",
            "ASmallCar::com.spilgames.api.SpilGamesServices::disconnect",
            "ASmallCar::flare.loaders.Flare3DLoader::_152",
            "ASmallCar::flare.loaders.Flare3DLoader::_161",
            "ASmallCar::flare.loaders.Flare3DLoader::_167",
            "ASmallCar::flare.loaders.Flare3DLoader::_170",
            "ASmallCar::flare.loaders.Flare3DLoader::_173",
            "ASmallCar::flare.loaders.Flare3DLoader::_188",
            "ASmallCar::flare.loaders.Flare3DLoader::_215",
            "ASmallCar::flare.loaders.Flare3DLoader::loadBytes",
            "ASmallCar::flare.materials.MultiMaterial::clone",
            "ASmallCar::flare.system.Device3D::addPolys",
            "ASmallCar::jiglib.physics.PhysicsSystem::setSolverType",
            "ASmallCar::mochi.as3.MochiAd::rpc",
            "ASmallCar::mochi.as3.MochiServices::onEvent",
            "ASmallCar::mochi.as3.MochiServices::warnID",
            "ATV_Cross_Canada::_-3F._-52::_-82",
            "ATV_Cross_Canada::_-3F._-EG::_-82",
            "ATV_Cross_Canada::_-7i._-NT::_-8Q",
            "ATV_Cross_Canada::_-J1.Level::runProcess",
            "ATV_Cross_Canada::_-J1._-9W::_-CI",
            "ATV_Cross_Canada::_-O4._-HY::_-78",
            "ATV_Cross_Canada::_-O4._-HY::onEvent",
            "ATV_Cross_Canada::_-RG._-3K::_-6n",
            "ATV_Cross_Canada::_-RG._-3K::_-Hf",
            "ATV_Cross_Canada::_-RG._-3K::_-Qu",
            "ATV_Cross_Canada::_-s.in ::dispatch",
            "ATV_Cross_Canada::engine.comp.phys.PhysCons2::createLine",
            "ATV_Cross_Canada::engine.comp.phys.PhysCons2::createPoint",
            "ATV_Cross_Canada::engine.comp.phys.PhysCons::getBody",
            "ATV_Cross_Canada::engine.logic.BaseLogic::getComp",
            "ATV_Cross_Canada::engine.logic.BaseLogic::getCompNoNode",
            "ATV_Cross_Canada::engine.logic.LogicSession::handleCbBegin",
            "ATV_Cross_Canada::engine.logic.LogicSessionHud::stuntKey",
            "ATV_Cross_Canada::engine.logic.LogicSessionRagdoll::update",
            "BO_Awesome_Ranger::ImageEngine::createButton",
            "BO_Awesome_Ranger::ImageEngine::createImage",
            "BO_Awesome_Ranger::ImageEngine::drawTutorial",
            "BO_Awesome_Ranger::LevelEngine::getLevel",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::collectVG",
            "BO_Awesome_Ranger::alternativa.engine3d.core.VG::draw",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-1o",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-2I",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-3q",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-4Z",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-4q",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-5x",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-6U",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-75",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::try",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::use ",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::group",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::removeVertex",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::removeVertexById",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::weldNormals",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.assets.AssetPortalLogo::ini",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.classes.GameAllianzApiExtended::action",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.utils.GlobalTrace::_-7N",
            "BO_Neo_Rider::build_fla.MainTimeline::objSet",
            "BO_Neo_Rider::mochi.as3.MochiAd::rpc",
            "BO_Neo_Rider::mochi.as3.MochiServices::onEvent",
            "BO_Neo_Rider::mochi.as3.MochiServices::warnID",
            "BO_Neo_Rider::mochi.as3.MochiSync::triggerEvent",
            "BO_Neo_Rider::sandy.core.scenegraph.ATransformable::getPosition",
            "BO_Neo_Rider::sandy.core.scenegraph.Sound3D::get soundSource",
            "BO_Neo_Rider::sandy.math.ColorMath::calculateLitColour",
            "BO_Twin_Drivers_Level_9000::Game::addAchievesByTravel",
            "BO_Twin_Drivers_Level_9000::Game::addNewCarToLane",
            "BO_Twin_Drivers_Level_9000::Game::addNewObjects",
            "BO_Twin_Drivers_Level_9000::Game::getGameModeFormat",
            "BO_Twin_Drivers_Level_9000::Game::initItem",
            "BO_Twin_Drivers_Level_9000::Game::keyEvent",
            "BO_Twin_Drivers_Level_9000::Game::keyPress",
            "BO_Twin_Drivers_Level_9000::Game::setCarDimension",
            "BO_Twin_Drivers_Level_9000::Game::setMyCarSound",
            "BO_Twin_Drivers_Level_9000::Screen::getDisableHint",
            "BO_Twin_Drivers_Level_9000::Screen::showPrevScreen",
            "BO_Twin_Drivers_Level_9000::Screen::update",
            "BO_Twin_Drivers_Level_9000::com.adobe.serialization.json.JSONDecoder::parseValue",
            "BO_Twin_Drivers_Level_9000::com.adobe.serialization.json.JSONEncoder::escapeString",
            "BO_Twin_Drivers_Level_9000::com.adobe.serialization.json.JSONTokenizer::getNextToken",
            "BO_Twin_Drivers_Level_9000::com.adobe.serialization.json.JSONTokenizer::readString",
            "BO_Twin_Drivers_Level_9000::com.adobe.serialization.json.JSONTokenizer::skipComments",
            "BO_Twin_Drivers_Level_9000::lib.GInput::getKey",
            "BO_Twin_Drivers_Level_9000::lib.GWidget::write",
        ],
    },
    RemainderGroup {
        precondition: "switch dispatch region is irreducible",
        must_stay_refused: true,
        anonymous: 0,
        members: &[
            "10_More_Bullets::entity.weapon.Weapon::update",
            "10_More_Bullets::logic.level.LevelFactory::addOneSpecialWave",
            "10_More_Bullets::logic.level.event.LevelEventBulletCombo::doTrigger",
            "10_More_Bullets::logic.level.sub.LA0::onCatchLoot",
            "10_More_Bullets::logic.level.sub.LPVP0::onCatchLoot",
            "10_More_Bullets::logic.level.sub.LevelPvp::doAddOneBooster",
            "10_More_Bullets::logic.level.sub.LevelPvp::getIsPlayerFrozen",
            "10_More_Bullets::logic.level.sub.LevelPvp::onLevelStart",
            "10_More_Bullets::nape.space.Space::interactionType",
            "10_More_Bullets::player.PlayerHelper::getGrabbersSpeedBonus",
            "10_More_Bullets::zpp_nape.geom.ZPP_Collide::flowCollide",
            "10_More_Bullets::zpp_nape.geom.ZPP_Monotone::decompose",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::narrowPhase",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_Body::remove_node",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSet::remove_node",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_CbSetPair::remove_node",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionPair::remove_node",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_PartitionVertex::remove_node",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleEvent::remove_node",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleSeg::remove_node",
            "10_More_Bullets::zpp_nape.util.ZPP_Set_ZPP_SimpleVert::remove_node",
            "ATV_Cross_Canada::_-JM._-I-::_-6w",
            "ATV_Cross_Canada::_-JM._-I-::_-8v",
            "ATV_Cross_Canada::_-JM._-I-::_-EA",
            "ATV_Cross_Canada::_-JM._-I-::_-MD",
            "ATV_Cross_Canada::_-JM._-Ld::broadphase",
            "BO_Neo_Rider::sandy.core.scenegraph.Sprite2D::cull",
        ],
    },
    RemainderGroup {
        precondition: "unreconciled scope height",
        must_stay_refused: false,
        anonymous: 0,
        members: &[
            "10_More_Bullets::flash.Boot::__string_rec",
            "10_More_Bullets::nape.callbacks.CbTypeList::filter",
            "10_More_Bullets::nape.callbacks.ListenerList::filter",
            "10_More_Bullets::nape.constraint.ConstraintList::filter",
            "10_More_Bullets::nape.dynamics.ArbiterList::filter",
            "10_More_Bullets::nape.dynamics.ContactList::filter",
            "10_More_Bullets::nape.dynamics.InteractionGroupList::filter",
            "10_More_Bullets::nape.geom.ConvexResultList::filter",
            "10_More_Bullets::nape.geom.GeomPolyList::filter",
            "10_More_Bullets::nape.geom.RayResultList::filter",
            "10_More_Bullets::nape.geom.Vec2List::filter",
            "10_More_Bullets::nape.phys.BodyList::filter",
            "10_More_Bullets::nape.phys.CompoundList::filter",
            "10_More_Bullets::nape.phys.InteractorList::filter",
            "10_More_Bullets::nape.shape.EdgeList::filter",
            "10_More_Bullets::nape.shape.ShapeList::filter",
            "1942_Battles_In_The_Sky::org.flixel.FlxSave::bind",
            "1942_Battles_In_The_Sky::org.flixel.FlxSave::forceSave",
            "ASmallCar::com.junkbyte.console.core.Executer::exec",
            "ASmallCar::com.junkbyte.console.core.Graphing::add",
            "ASmallCar::com.junkbyte.console.core.Graphing::update",
            "ASmallCar::com.junkbyte.console.core.ObjectsMonitor::update",
            "ASmallCar::flare.primitives.MirrorPlane::_41",
            "ASmallCar::mochi.as3.MochiAd::load",
            "ASmallCar::mochi.as3.MochiUserData::completeHandler",
            "ATV_Cross_Canada::Playtomic._-4i::_-Pb",
            "ATV_Cross_Canada::Playtomic._-66::_-Iz",
            "ATV_Cross_Canada::Playtomic._-6v::_-0H",
            "ATV_Cross_Canada::Playtomic._-6v::_-0O",
            "ATV_Cross_Canada::Playtomic._-BE::_-LC",
            "ATV_Cross_Canada::Playtomic._-Dw::_-7f",
            "ATV_Cross_Canada::Playtomic._-JF::_-Gt",
            "ATV_Cross_Canada::Playtomic._-P8::_-2I",
            "ATV_Cross_Canada::_-4D.Array2_nape_space_UniformCell::_-6c",
            "ATV_Cross_Canada::_-7J._-Io::init",
            "ATV_Cross_Canada::_-7i._-AD::in",
            "ATV_Cross_Canada::_-98._-HS::remove",
            "ATV_Cross_Canada::_-CC._-5i::clear",
            "ATV_Cross_Canada::_-CC._-5i::splice",
            "ATV_Cross_Canada::_-CC._-6C::remove",
            "ATV_Cross_Canada::_-CC._-7A::clear",
            "ATV_Cross_Canada::_-CC._-AO::clear",
            "ATV_Cross_Canada::_-CC._-Aa::clear",
            "ATV_Cross_Canada::_-CC._-GM::splice",
            "ATV_Cross_Canada::_-CC._-Mr::remove",
            "ATV_Cross_Canada::_-CC._-Qv::remove",
            "ATV_Cross_Canada::_-CC._-y::clear",
            "ATV_Cross_Canada::_-E3.TweenMax::_-KW",
            "ATV_Cross_Canada::_-E3.TweenMax::_-Qh",
            "ATV_Cross_Canada::_-Fw._-Fn::_-KA",
            "ATV_Cross_Canada::_-Fw._-Fn::killProps",
            "ATV_Cross_Canada::_-Fw._-Le::init",
            "ATV_Cross_Canada::_-Hj::toString",
            "ATV_Cross_Canada::_-I1._-4z::removeShape",
            "ATV_Cross_Canada::_-J1.Level::_-Ch",
            "ATV_Cross_Canada::_-J1._-1m::destroy",
            "ATV_Cross_Canada::_-JM._-I-::_-3Z",
            "ATV_Cross_Canada::_-JM._-I-::_-7a",
            "ATV_Cross_Canada::_-JM._-I-::_-Eq",
            "ATV_Cross_Canada::_-JM._-I-::removeConstraint",
            "ATV_Cross_Canada::_-JM._-Ld::clear_special",
            "ATV_Cross_Canada::_-JM._-N0::clear",
            "ATV_Cross_Canada::_-O4._-1D::_-PA",
            "ATV_Cross_Canada::_-O4.use ::_-1l",
            "ATV_Cross_Canada::_-Qp._-36::_-0N",
            "ATV_Cross_Canada::_-Qp._-36::_-RL",
            "ATV_Cross_Canada::_-Qp._-6X::_-0N",
            "ATV_Cross_Canada::_-Qp._-HM::_-Ca",
            "ATV_Cross_Canada::_-Qp._-Lm::_-Pp",
            "ATV_Cross_Canada::_-Qp._-Qc::_-0N",
            "ATV_Cross_Canada::_-Qp._-Qc::_-OE",
            "ATV_Cross_Canada::_-RG._-2o::_-0t",
            "ATV_Cross_Canada::_-RG._-3K::_-A2",
            "ATV_Cross_Canada::_-g._-FZ::removeFromBodies",
            "ATV_Cross_Canada::engine.logic.LogicZombie2::restart",
            "ATV_Cross_Canada::flash._-Hw::_-9R",
            "ATV_Cross_Canada::flash._-Qa::_-Qa",
            "BO_Awesome_Ranger::ParticleEngine::addRadialParticle",
            "BO_Awesome_Ranger::ParticleEngine::dispose",
            "BO_Awesome_Ranger::ParticleEngine::update",
            "BO_Awesome_Ranger::alternativa.engine3d.containers.ConflictContainer::_-19",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Camera3D::calculateRay",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Camera3D::checkInDebug",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Camera3D::clip",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Camera3D::cull",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Camera3D::sortByAverageZ",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Camera3D::sortByDynamicBSP",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Canvas::removeChildren",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Light3D::setParent",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3D::dispatchEvent",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::checkIntersection",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::clonePropertiesFrom",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::collectPlanes",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::colorizeVG",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::contains",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::getChildIndex",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::removeChildAt",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::split",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3DContainer::updateBounds",
            "BO_Awesome_Ranger::alternativa.engine3d.core.VG::class",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Vertex::createList",
            "BO_Awesome_Ranger::alternativa.engine3d.core.View::_-63",
            "BO_Awesome_Ranger::alternativa.engine3d.core.View::removeChildren",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-44",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::static",
            "BO_Awesome_Ranger::alternativa.engine3d.materials.FillMaterial::draw",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::calculateFacesNormals",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::collectPlanes",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::containsFace",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::containsVertexWithId",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::do ",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::drawFaces",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::get faces",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::get vertices",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::prepareFaces",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::removeFace",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::removeFaceById",
            "BO_Awesome_Ranger::alternativa.engine3d.primitives.Box::Box",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.GameAllianzApiLocalization::getTranslationById",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.GameAllianzApiLocalization::getTranslationByWordId",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.GameAllianzApiLocalization::getTranslationByWordIdAndLanguage",
            "BO_Awesome_Ranger::containers.GameContainer::reloadLevel",
            "BO_Awesome_Ranger::containers.IntroContainer::_-0a",
            "BO_Awesome_Ranger::levels.Level10::_-5v",
            "BO_Awesome_Ranger::levels.Level12:: in",
            "BO_Awesome_Ranger::levels.Level12::_-3S",
            "BO_Awesome_Ranger::levels.Level12::_-5v",
            "BO_Awesome_Ranger::levels.Level13::_-03",
            "BO_Awesome_Ranger::levels.Level13::_-5v",
            "BO_Awesome_Ranger::levels.Level13::_-7I",
            "BO_Awesome_Ranger::levels.Level14::_-6w",
            "BO_Awesome_Ranger::levels.Level16::in",
            "BO_Awesome_Ranger::levels.Level17::in",
            "BO_Awesome_Ranger::levels.Level18::_-4m",
            "BO_Awesome_Ranger::levels.Level18::_-7A",
            "BO_Awesome_Ranger::levels.Level19::_-1d",
            "BO_Awesome_Ranger::levels.Level20:: in",
            "BO_Awesome_Ranger::levels.Level20::_-5v",
            "BO_Awesome_Ranger::levels.Level21::_-6p",
            "BO_Awesome_Ranger::levels.Level2::_-3J",
            "BO_Awesome_Ranger::levels.Level3::_-03",
            "BO_Awesome_Ranger::levels.Level5::_-6w",
            "BO_Awesome_Ranger::levels.Level7::_-3S",
            "BO_Awesome_Ranger::levels.Level7::_-6w",
            "BO_Awesome_Ranger::levels.Level9::_-4x",
            "BO_Neo_Rider::mochi.as3.MochiAd::load",
            "BO_Neo_Rider::mochi.as3.MochiServices::createEmptyMovieClip",
            "BO_Neo_Rider::mochi.as3.MochiUserData::completeHandler",
            "BO_Twin_Drivers_Level_9000::com.adobe.serialization.json.JSONEncoder::objectToString",
        ],
    },
    RemainderGroup {
        precondition: "unreconciled scope values",
        must_stay_refused: true,
        anonymous: 1,
        members: &[
            "ATV_Cross_Canada::Playtomic._-Dw::_-DM",
            "ATV_Cross_Canada::_-O4._-HY::_-19",
            "ATV_Cross_Canada::_-O4.use ::_-K3",
            "ATV_Cross_Canada::_-O4.use ::request",
            "ATV_Cross_Canada::_-OH._-RO::GC_utils_GCSWFConnection_receive",
            "ATV_Cross_Canada::_-OH._-RO::close",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.GameAllianzApiLocalization::getWordById",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.classes.GameAllianzApiExtended::_-W",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.classes.GameAllianzApiGlobal::get domain",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.classes.GameAllianzApiGlobal::set stage",
            "BO_Neo_Rider::mochi.as3.MochiUserData::performCallback",
        ],
    },
    RemainderGroup {
        precondition: "unreconciled stack height",
        must_stay_refused: true,
        anonymous: 7,
        members: &[
            "10_More_Bullets::com.hurlant.crypto.symmetric.XTeaKey::dispose",
            "10_More_Bullets::com.hurlant.math.BigInteger::dispose",
            "10_More_Bullets::com.hurlant.math.BigInteger::divRemTo",
            "10_More_Bullets::nape.callbacks.CbTypeList::foreach",
            "10_More_Bullets::nape.callbacks.ListenerList::foreach",
            "10_More_Bullets::nape.constraint.ConstraintList::foreach",
            "10_More_Bullets::nape.dynamics.ArbiterList::foreach",
            "10_More_Bullets::nape.dynamics.ContactList::foreach",
            "10_More_Bullets::nape.dynamics.InteractionGroupList::foreach",
            "10_More_Bullets::nape.geom.ConvexResultList::foreach",
            "10_More_Bullets::nape.geom.GeomPoly::GeomPoly",
            "10_More_Bullets::nape.geom.GeomPoly::get",
            "10_More_Bullets::nape.geom.GeomPolyList::foreach",
            "10_More_Bullets::nape.geom.RayResultList::foreach",
            "10_More_Bullets::nape.geom.Vec2::unit",
            "10_More_Bullets::nape.geom.Vec2List::copy",
            "10_More_Bullets::nape.geom.Vec2List::foreach",
            "10_More_Bullets::nape.phys.Body::toString",
            "10_More_Bullets::nape.phys.BodyList::foreach",
            "10_More_Bullets::nape.phys.CompoundList::foreach",
            "10_More_Bullets::nape.phys.InteractorList::foreach",
            "10_More_Bullets::nape.shape.EdgeList::foreach",
            "10_More_Bullets::nape.shape.Polygon::Polygon",
            "10_More_Bullets::nape.shape.ShapeList::foreach",
            "10_More_Bullets::nape.util.BitmapDebug::drawFilledPolygon",
            "10_More_Bullets::nape.util.BitmapDebug::drawPolygon",
            "10_More_Bullets::nape.util.ShapeDebug::drawFilledPolygon",
            "10_More_Bullets::nape.util.ShapeDebug::drawPolygon",
            "10_More_Bullets::zpp_nape.geom.ZPP_PartitionVertex::sort",
            "10_More_Bullets::zpp_nape.geom.ZPP_SimpleSweep::edge_lt",
            "10_More_Bullets::zpp_nape.geom.ZPP_SweepDistance::dynamicSweep",
            "10_More_Bullets::zpp_nape.geom.ZPP_SweepDistance::staticSweep",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::continuousEvent",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::freshInteractorType",
            "10_More_Bullets::zpp_nape.space.ZPP_Space::freshListenerType",
            "10_More_Bullets::zpp_nape.space.ZPP_SweepPhase::shapesInAABB",
            "1942_Battles_In_The_Sky::gs.OverwriteManager::killVars",
            "1942_Battles_In_The_Sky::gs.TweenLite::killGarbage",
            "1942_Battles_In_The_Sky::gs.TweenLite::killTweensOf",
            "1942_Battles_In_The_Sky::gs.TweenMax::resume",
            "1942_Battles_In_The_Sky::gs.TweenMax::set enabled",
            "1942_Battles_In_The_Sky::gs.plugins.BezierPlugin::init",
            "1942_Battles_In_The_Sky::gs.plugins.BezierPlugin::killProps",
            "1942_Battles_In_The_Sky::org.flixel.FlxU::ceil",
            "1942_Battles_In_The_Sky::org.flixel.FlxU::solveXCollision",
            "1942_Battles_In_The_Sky::org.flixel.FlxU::solveYCollision",
            "ASmallCar::com.greensock.TweenLite::killTweensOf",
            "ASmallCar::com.greensock.TweenLite::killVars",
            "ASmallCar::com.greensock.TweenLite::updateAll",
            "ASmallCar::com.greensock.plugins.BezierPlugin::init",
            "ASmallCar::com.greensock.plugins.BezierPlugin::killProps",
            "ASmallCar::com.junkbyte.console.core.CommandTools::inspect",
            "ASmallCar::com.junkbyte.console.core.KeyBinder::bindKey",
            "ASmallCar::com.junkbyte.console.core.MemoryMonitor::unwatch",
            "ASmallCar::com.junkbyte.console.core.MemoryMonitor::update",
            "ASmallCar::com.junkbyte.console.view.GraphingPanel::update",
            "ASmallCar::com.junkbyte.console.view.PanelsManager::updateObjMonitors",
            "ASmallCar::com.junkbyte.console.vos.WeakObject::set",
            "ASmallCar::flare.core.Mesh3D::changePolyMaterial",
            "ASmallCar::flare.core.Mesh3D::dispose",
            "ASmallCar::flare.core.Mesh3D::replaceMaterial",
            "ASmallCar::flare.core.Surface3D::removePoly",
            "ASmallCar::mochi.as3.MochiAd::_cleanup",
            "ATV_Cross_Canada::Playtomic._-4i::_-I2",
            "ATV_Cross_Canada::Playtomic._-BE::_-MM",
            "ATV_Cross_Canada::Playtomic._-Dg::_-Z",
            "ATV_Cross_Canada::Playtomic._-FA::CustomMetric",
            "ATV_Cross_Canada::Playtomic._-FA::_-FM",
            "ATV_Cross_Canada::Playtomic._-FA::_-Ge",
            "ATV_Cross_Canada::Playtomic._-P8::_-Z",
            "ATV_Cross_Canada::_-13._-2B::_-2B",
            "ATV_Cross_Canada::_-13._-2B::each",
            "ATV_Cross_Canada::_-13._-O7::renderTime",
            "ATV_Cross_Canada::_-3F.for::_-82",
            "ATV_Cross_Canada::_-4D._-0g::_-Kx",
            "ATV_Cross_Canada::_-7i._-1E::show",
            "ATV_Cross_Canada::_-7i._-AD::show",
            "ATV_Cross_Canada::_-7i._-Pj::enable",
            "ATV_Cross_Canada::_-98._-3A::_-6l",
            "ATV_Cross_Canada::_-98._-3A::_-8k",
            "ATV_Cross_Canada::_-98._-3A::_-Ab",
            "ATV_Cross_Canada::_-98._-3A::_-IP",
            "ATV_Cross_Canada::_-98._-3A::_-MW",
            "ATV_Cross_Canada::_-98._-3A::clone",
            "ATV_Cross_Canada::_-98._-Q9::_-0Y",
            "ATV_Cross_Canada::_-98._-Q9::_-F4",
            "ATV_Cross_Canada::_-98._-Q9::_-Lh",
            "ATV_Cross_Canada::_-CC._-1P::_-Px",
            "ATV_Cross_Canada::_-CC._-1P::add",
            "ATV_Cross_Canada::_-CC._-1P::insert",
            "ATV_Cross_Canada::_-CC._-2N::_-Px",
            "ATV_Cross_Canada::_-CC._-2N::add",
            "ATV_Cross_Canada::_-CC._-2N::get",
            "ATV_Cross_Canada::_-CC._-2N::insert",
            "ATV_Cross_Canada::_-CC._-5i::_-Px",
            "ATV_Cross_Canada::_-CC._-5i::add",
            "ATV_Cross_Canada::_-CC._-5i::insert",
            "ATV_Cross_Canada::_-CC._-6C::_-Px",
            "ATV_Cross_Canada::_-CC._-6C::add",
            "ATV_Cross_Canada::_-CC._-6C::insert",
            "ATV_Cross_Canada::_-CC._-7A::_-Px",
            "ATV_Cross_Canada::_-CC._-7A::add",
            "ATV_Cross_Canada::_-CC._-7A::insert",
            "ATV_Cross_Canada::_-CC._-7P::_-Px",
            "ATV_Cross_Canada::_-CC._-7P::add",
            "ATV_Cross_Canada::_-CC._-7P::insert",
            "ATV_Cross_Canada::_-CC._-AO::_-Px",
            "ATV_Cross_Canada::_-CC._-AO::add",
            "ATV_Cross_Canada::_-CC._-AO::insert",
            "ATV_Cross_Canada::_-CC._-Aa::_-Px",
            "ATV_Cross_Canada::_-CC._-Aa::add",
            "ATV_Cross_Canada::_-CC._-Aa::insert",
            "ATV_Cross_Canada::_-CC._-FE::_-Px",
            "ATV_Cross_Canada::_-CC._-FE::add",
            "ATV_Cross_Canada::_-CC._-FE::insert",
            "ATV_Cross_Canada::_-CC._-GM::_-Px",
            "ATV_Cross_Canada::_-CC._-GM::add",
            "ATV_Cross_Canada::_-CC._-GM::insert",
            "ATV_Cross_Canada::_-CC._-Il::_-Px",
            "ATV_Cross_Canada::_-CC._-Il::add",
            "ATV_Cross_Canada::_-CC._-Il::insert",
            "ATV_Cross_Canada::_-CC._-Ly::_-Px",
            "ATV_Cross_Canada::_-CC._-Ly::add",
            "ATV_Cross_Canada::_-CC._-Ly::insert",
            "ATV_Cross_Canada::_-CC._-Mr::_-Px",
            "ATV_Cross_Canada::_-CC._-Mr::add",
            "ATV_Cross_Canada::_-CC._-Mr::insert",
            "ATV_Cross_Canada::_-CC._-QD::_-Px",
            "ATV_Cross_Canada::_-CC._-QD::add",
            "ATV_Cross_Canada::_-CC._-QD::insert",
            "ATV_Cross_Canada::_-CC._-Qv::_-Px",
            "ATV_Cross_Canada::_-CC._-Qv::add",
            "ATV_Cross_Canada::_-CC._-Qv::insert",
            "ATV_Cross_Canada::_-CC._-y::_-Px",
            "ATV_Cross_Canada::_-CC._-y::add",
            "ATV_Cross_Canada::_-CC._-y::insert",
            "ATV_Cross_Canada::_-CC.super::_-Px",
            "ATV_Cross_Canada::_-CC.super::add",
            "ATV_Cross_Canada::_-CC.super::insert",
            "ATV_Cross_Canada::_-CC.true::_-Px",
            "ATV_Cross_Canada::_-CC.true::add",
            "ATV_Cross_Canada::_-CC.true::insert",
            "ATV_Cross_Canada::_-E3.TweenMax::invalidate",
            "ATV_Cross_Canada::_-E3.TweenMax::set timeScale",
            "ATV_Cross_Canada::_-E3._-Jr::_-Jr",
            "ATV_Cross_Canada::_-E3._-Jr::_-LT",
            "ATV_Cross_Canada::_-E3._-Jr::_-PL",
            "ATV_Cross_Canada::_-E3._-Jr::killTweensOf",
            "ATV_Cross_Canada::_-Fw._-DO::_-LH",
            "ATV_Cross_Canada::_-Fw._-DO::onInitTween",
            "ATV_Cross_Canada::_-Fw._-Fn::_-7u",
            "ATV_Cross_Canada::_-Fw._-Nj::init",
            "ATV_Cross_Canada::_-Fw._-Nj::killProps",
            "ATV_Cross_Canada::_-I1._-48::addObject",
            "ATV_Cross_Canada::_-J1.Frame::_-Bl",
            "ATV_Cross_Canada::_-J1.Frame::timeoutSet",
            "ATV_Cross_Canada::_-J1._-4h::removeKey",
            "ATV_Cross_Canada::_-J1._-5V::_-Nf",
            "ATV_Cross_Canada::_-JM._-I-::_-1",
            "ATV_Cross_Canada::_-JM._-I-::_-44",
            "ATV_Cross_Canada::_-JM._-I-::_-83",
            "ATV_Cross_Canada::_-JM._-I-::_-9m",
            "ATV_Cross_Canada::_-JM._-I-::_-Ai",
            "ATV_Cross_Canada::_-JM._-I-::_-Ar",
            "ATV_Cross_Canada::_-JM._-I-::_-Bm",
            "ATV_Cross_Canada::_-JM._-I-::_-DB",
            "ATV_Cross_Canada::_-JM._-I-::_-JH",
            "ATV_Cross_Canada::_-JM._-I-::_-QY",
            "ATV_Cross_Canada::_-JM._-I-::addConstraint",
            "ATV_Cross_Canada::_-JM._-I-::addParticle",
            "ATV_Cross_Canada::_-JM._-I-::const",
            "ATV_Cross_Canada::_-JM._-I-::step",
            "ATV_Cross_Canada::_-JM._-I-::wakeConstraint",
            "ATV_Cross_Canada::_-JM._-Ld::_-DI",
            "ATV_Cross_Canada::_-JM._-Ld::_-K9",
            "ATV_Cross_Canada::_-JM._-Ld::addObject",
            "ATV_Cross_Canada::_-JM._-Ld::objectAtPoint",
            "ATV_Cross_Canada::_-JM._-Ld::rayCast",
            "ATV_Cross_Canada::_-JM._-Ld::removeObject",
            "ATV_Cross_Canada::_-JM._-Ld::syncParticle",
            "ATV_Cross_Canada::_-JM._-Ld::syncShape",
            "ATV_Cross_Canada::_-JM._-Ld::visitate",
            "ATV_Cross_Canada::_-Nh._-K0::over",
            "ATV_Cross_Canada::_-Nh._-LK::onShow",
            "ATV_Cross_Canada::_-OH._-RO::_-RO",
            "ATV_Cross_Canada::_-Qp._-0D::_-JX",
            "ATV_Cross_Canada::_-Qp._-0D::_-L-",
            "ATV_Cross_Canada::_-Qp._-36::_-L-",
            "ATV_Cross_Canada::_-Qp._-36::preStep",
            "ATV_Cross_Canada::_-Qp._-36::static",
            "ATV_Cross_Canada::_-Qp._-5D::_-JX",
            "ATV_Cross_Canada::_-Qp._-6X::_-L-",
            "ATV_Cross_Canada::_-Qp._-6X::preStep",
            "ATV_Cross_Canada::_-Qp._-6X::static",
            "ATV_Cross_Canada::_-Qp._-Lm::_-L-",
            "ATV_Cross_Canada::_-Qp._-Lm::static",
            "ATV_Cross_Canada::_-Qp._-OG::_-02",
            "ATV_Cross_Canada::_-Qp._-OG::_-8L",
            "ATV_Cross_Canada::_-Qp._-OG::_-8f",
            "ATV_Cross_Canada::_-Qp._-OG::_-9Q",
            "ATV_Cross_Canada::_-Qp._-OG::_-FG",
            "ATV_Cross_Canada::_-Qp._-OG::_-Fe",
            "ATV_Cross_Canada::_-Qp._-OG::_-GV",
            "ATV_Cross_Canada::_-Qp._-OG::_-Kd",
            "ATV_Cross_Canada::_-Qp._-OG::_-Ls",
            "ATV_Cross_Canada::_-Qp._-OG::_-N2",
            "ATV_Cross_Canada::_-Qp._-OG::_-Q1",
            "ATV_Cross_Canada::_-Qp._-OG::circle2circle_false_false_true_true",
            "ATV_Cross_Canada::_-Qp._-OG::circle2circle_query_false_false_true_true",
            "ATV_Cross_Canada::_-Qp._-OG::circle2circle_query_true_true_true_true",
            "ATV_Cross_Canada::_-Qp._-OG::circle2circle_true_true_true_true",
            "ATV_Cross_Canada::_-Qp._-OG::circle2particle_false_false_true",
            "ATV_Cross_Canada::_-Qp._-OG::circle2particle_true_true_true",
            "ATV_Cross_Canada::_-Qp._-OG::circle2poly_false_false_true_true",
            "ATV_Cross_Canada::_-Qp._-OG::circle2poly_test",
            "ATV_Cross_Canada::_-Qp._-OG::circle2poly_true_true_true_true",
            "ATV_Cross_Canada::_-Qp._-OG::poly2particle_false_false_true",
            "ATV_Cross_Canada::_-Qp._-OG::poly2particle_true_true_true",
            "ATV_Cross_Canada::_-Qp._-OG::poly2poly_false_false_true_true",
            "ATV_Cross_Canada::_-Qp._-OG::poly2poly_true_true_true_true",
            "ATV_Cross_Canada::_-Qp._-Qc::_-L-",
            "ATV_Cross_Canada::_-Qp._-Qc::static",
            "ATV_Cross_Canada::_-RG._-3K::_-Y",
            "ATV_Cross_Canada::_-RG._-ME::_-3W",
            "ATV_Cross_Canada::_-g._-FZ::addToBodies",
            "ATV_Cross_Canada::_-g._-FZ::body_list",
            "ATV_Cross_Canada::engine.comp.NodeComp::NodeComp",
            "ATV_Cross_Canada::engine.comp.view.ViewLayer::ViewLayer",
            "ATV_Cross_Canada::engine.comp.view.ViewLayer::update",
            "ATV_Cross_Canada::engine.logic.BaseLogic::getDependencies",
            "ATV_Cross_Canada::engine.logic.LogicDamageCar::touching",
            "ATV_Cross_Canada::engine.logic.LogicImpact::frameDebug",
            "ATV_Cross_Canada::engine.logic.LogicParticles::draw",
            "ATV_Cross_Canada::engine.logic.LogicParticles::drawFront",
            "ATV_Cross_Canada::engine.logic.LogicSessionHud::goUp",
            "ATV_Cross_Canada::engine.logic.LogicSessionHud::restart",
            "ATV_Cross_Canada::engine.logic.LogicSessionMap::update",
            "ATV_Cross_Canada::engine.logic.LogicVehicle::global",
            "ATV_Cross_Canada::engine.logic.LogicVehicle::move",
            "ATV_Cross_Canada::function.Shape::Shape",
            "BO_Awesome_Ranger::Equations::easeOutExpo",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Camera3D::removeFromDebug",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Canvas::getChildCanvas",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Debug::drawBounds",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Light3D::checkBoundsIntersection",
            "BO_Awesome_Ranger::alternativa.engine3d.core.Object3D::removeEventListener",
            "BO_Awesome_Ranger::alternativa.engine3d.core.VG::_-1C",
            "BO_Awesome_Ranger::alternativa.engine3d.core.View::_-5d",
            "BO_Awesome_Ranger::alternativa.engine3d.core.View::getChildCanvas",
            "BO_Awesome_Ranger::alternativa.engine3d.loaders.Parser3DS::_-2v",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::addVerticesAndFaces",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::calculateResolution",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::getVG",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Mesh::weldFaces",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Sprite3D::calculateResolution",
            "BO_Awesome_Ranger::alternativa.engine3d.objects.Sprite3D::getVG",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.utils.URL::get userinfo",
            "BO_Neo_Rider::build_fla.MainTimeline::cityMove",
            "BO_Neo_Rider::mochi.as3.MochiAd::_cleanup",
            "BO_Neo_Rider::mochi.as3.MochiServices::disconnect",
            "BO_Neo_Rider::sandy.core.Renderer::addToDisplayList",
            "BO_Neo_Rider::sandy.core.data.Polygon::Polygon",
            "BO_Neo_Rider::sandy.core.data.Pool::get nextPoint3D",
            "BO_Neo_Rider::sandy.core.data.Pool::get nextUV",
            "BO_Neo_Rider::sandy.core.data.Pool::get nextVertex",
            "BO_Neo_Rider::sandy.core.data.Vertex::Vertex",
            "BO_Neo_Rider::sandy.core.scenegraph.Geometry3D::dispose",
            "BO_Neo_Rider::sandy.core.scenegraph.Node::Node",
            "BO_Neo_Rider::sandy.materials.BitmapMaterial::unlink",
            "BO_Neo_Rider::sandy.materials.Material::Material",
            "BO_Neo_Rider::sandy.materials.Material::unlink",
            "BO_Twin_Drivers_Level_9000::Screen::updateCar",
            "BO_Twin_Drivers_Level_9000::lib.GSound::updateChannelVolume",
        ],
    },
    RemainderGroup {
        precondition: "unreconciled stack merge",
        must_stay_refused: true,
        anonymous: 0,
        members: &[
            "10_More_Bullets::com.google.analytics.external.JavascriptProxy::call",
            "10_More_Bullets::com.google.analytics.external.JavascriptProxy::executeBlock",
            "ASmallCar::com.junkbyte.console.core.CommandTools::explode",
            "ASmallCar::com.junkbyte.console.core.Executer::execSimple",
            "ASmallCar::mochi.as3.MochiServices::disconnect",
            "ASmallCar::mochi.as3.MochiServices::onReceive",
            "ASmallCar::spill.localisation.SpilGame::get embedDomain",
            "ATV_Cross_Canada::_-O4._-HY::_-1t",
            "ATV_Cross_Canada::_-O4._-HY::_-2b",
            "ATV_Cross_Canada::_-O4._-HY::onReceive",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.assets.AssetButton::_-6N",
            "BO_Awesome_Ranger::com.gameallianz.api.as3.gui.Background::set active",
            "BO_Neo_Rider::mochi.as3.MochiServices::onReceive",
            "BO_Twin_Drivers_Level_9000::lib.GCookie::init",
        ],
    },
];

#[test]
fn the_tracked_remainder_holds_its_pinned_membership() {
    let fixtures: [(&str, &[u8]); 6] = [
        (
            "control_shapes",
            include_bytes!("../../../corpus/flash/avm2_disasm_oracle/control_shapes.swf"),
        ),
        (
            "opcode_breadth",
            include_bytes!("../../../corpus/flash/avm2_disasm_oracle/opcode_breadth.swf"),
        ),
        ("switch_merge", include_bytes!("fixtures/switch_merge.swf")),
        (
            "dispatch_shapes",
            include_bytes!("fixtures/dispatch_shapes.swf"),
        ),
        (
            "whitespace_short_circuit",
            include_bytes!("fixtures/whitespace_short_circuit.swf"),
        ),
        (
            "json_tokenizer",
            include_bytes!("fixtures/json_tokenizer_postincrement.swf"),
        ),
    ];
    let mut census: Census = Census::default();
    for (label, bytes) in fixtures {
        take_swf(&mut census, bytes, label);
    }
    eprintln!(
        "AS3 tracked remainder: {}/{} recovered, remainder {}",
        census.recovered,
        census.bodies,
        census.bodies - census.recovered
    );
    assert_eq!(
        census.bodies, 555,
        "this pin reads every body in the tracked compiler fixtures, so a shrinking population \
         would let it hold over almost nothing"
    );
    compare(&census, TRACKED_REMAINDER, "tracked fixtures");
}

#[test]
fn the_corpus_remainder_holds_its_pinned_membership() {
    let dir: PathBuf = common::as3_corpus_root();
    if !common::require_corpus("as3 remainder census", &dir) {
        return;
    }
    let mut census: Census = Census::default();
    let mut files: usize = 0;
    for entry in std::fs::read_dir(&dir).expect("read corpus") {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) != Some("swf") {
            continue;
        }
        files += 1;
        let label: String = path.file_stem().map_or_else(
            || "?".to_owned(),
            |name: &std::ffi::OsStr| name.to_string_lossy().into_owned(),
        );
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        take_swf(&mut census, &bytes, &label);
    }
    eprintln!(
        "AS3 corpus remainder: files={files} {}/{} recovered, remainder {}",
        census.recovered,
        census.bodies,
        census.bodies - census.recovered
    );
    assert_eq!(files, 19, "the pinned membership names bodies in 19 files");
    assert_eq!(census.bodies, 17917);
    assert_eq!(census.recovered, 16857);
    compare(&census, CORPUS_REMAINDER, "corpus");
}

#[test]
fn the_refusals_the_item_requires_are_separated_from_the_gaps() {
    let required: usize = CORPUS_REMAINDER
        .iter()
        .filter(|group: &&RemainderGroup| group.must_stay_refused)
        .fold(0usize, |total: usize, group: &RemainderGroup| {
            total + group.members.len() + group.anonymous
        });
    let total: usize = CORPUS_REMAINDER
        .iter()
        .fold(0usize, |running: usize, group: &RemainderGroup| {
            running + group.members.len() + group.anonymous
        });
    eprintln!("AS3 corpus remainder: {required}/{total} are refusals the item requires");
    assert_eq!(total, 1060);
    assert_eq!(
        required, 453,
        "a body counted here is one FEAT-028 names as a required refusal: a merge whose incoming \
         stacks disagree in depth, a dispatch entered backward or mid-region, an irreducible \
         dispatch region, an overlapping or backward handler merge, and a scope merge that would \
         collapse distinct allocations. Recovering one of these would be a defect, not an \
         improvement, so this number moving down needs the same scrutiny as a floor moving down"
    );
    for group in TRACKED_REMAINDER.iter().chain(CORPUS_REMAINDER) {
        assert!(
            !group.precondition.starts_with("other marker") && group.precondition != "unclassified",
            "every stopped body must land in a named precondition, and `{}` is the classifier \
             admitting it has none",
            group.precondition
        );
    }
}
